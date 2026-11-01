#!/usr/bin/env python3
"""KERNIX game-profile JSON snapshot store. Offline, no game or engine execution.

An immutable, content-addressed snapshot is written first. The pointer to the
current profile is then replaced atomically. Existing snapshots are never
overwritten. A corrupt or missing snapshot is rejected, not silently applied.
This is a reference storage layer, not yet integrated with Android.
"""
import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from kernix_game_profiles import profile_key, validate_profile, read_json

SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON = 65536

def encode(data):
    raw = (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(raw) > MAX_JSON:
        raise ValueError("PROFILE_TOO_LARGE")
    return raw

def file_digest(raw):
    return hashlib.sha256(raw).hexdigest()

def safe_root(root):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("ROOT_IS_SYMLINK")
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("INVALID_ROOT")
    return root

def check_regular(path):
    if path.is_symlink():
        raise ValueError("SYMLINK_NOT_ALLOWED")
    if path.exists() and not path.is_file():
        raise ValueError("EXPECTED_FILE")
    if path.exists() and path.stat().st_size > MAX_JSON:
        raise ValueError("OVERSIZED_STORED_JSON")

def atomic_new(path, raw):
    """Create an immutable snapshot without replacing any existing file."""
    check_regular(path)
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError("SNAPSHOT_HASH_COLLISION")
        return
    # Exclusive creation: prevents silent overwrites, including concurrent writers.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def atomic_replace(path, raw):
    check_regular(path)
    fd, tmp = tempfile.mkstemp(prefix=".kernix-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        check_regular(path)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def paths(root, game_sha):
    game_sha = profile_key(game_sha)
    root = safe_root(root)
    directory = root / game_sha
    if directory.is_symlink():
        raise ValueError("GAME_DIRECTORY_IS_SYMLINK")
    directory.mkdir(exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("INVALID_GAME_DIRECTORY")
    snapshots = directory / "snapshots"
    if snapshots.is_symlink():
        raise ValueError("SNAPSHOT_DIRECTORY_IS_SYMLINK")
    snapshots.mkdir(exist_ok=True)
    if snapshots.is_symlink() or not snapshots.is_dir():
        raise ValueError("INVALID_SNAPSHOT_DIRECTORY")
    return directory / "current.json", snapshots

def load_snapshot(snapshots, digest, registry):
    if not isinstance(digest, str) or not SHA.fullmatch(digest):
        raise ValueError("INVALID_SNAPSHOT_ID")
    path = snapshots / (digest + ".json")
    check_regular(path)
    if not path.is_file():
        raise ValueError("SNAPSHOT_MISSING")
    raw = path.read_bytes()
    if file_digest(raw) != digest:
        raise ValueError("SNAPSHOT_INTEGRITY_FAILURE")
    profile = json.loads(raw)
    validate_profile(profile, registry)
    return profile

def current_digest(pointer):
    check_regular(pointer)
    if not pointer.exists():
        return None
    obj = json.loads(pointer.read_text(encoding="utf-8"))
    if set(obj) != {"schema", "snapshot"} or obj["schema"] != "kernix.game-pointer.v1":
        raise ValueError("INVALID_CURRENT_POINTER")
    if not isinstance(obj["snapshot"], str) or not SHA.fullmatch(obj["snapshot"]):
        raise ValueError("INVALID_CURRENT_SNAPSHOT_ID")
    return obj["snapshot"]

def save(root, profile, registry, expected_current=None):
    validate_profile(profile, registry)
    pointer, snapshots = paths(root, profile["game_sha256"])
    old = current_digest(pointer)
    if expected_current is not None and expected_current != old:
        raise ValueError("STALE_PROFILE_UPDATE")
    if old is not None:
        old_profile = load_snapshot(snapshots, old, registry)
        if old_profile["game_sha256"] != profile["game_sha256"]:
            raise ValueError("EXISTING_PROFILE_WRONG_GAME")
    raw = encode(profile)
    digest = file_digest(raw)
    atomic_new(snapshots / (digest + ".json"), raw)
    atomic_replace(pointer, encode({"schema":"kernix.game-pointer.v1","snapshot":digest}))
    return {"saved_snapshot":digest,"previous_snapshot":old,"game_sha256":profile["game_sha256"]}

def restore(root, game_sha, digest, registry, expected_current=None):
    pointer, snapshots = paths(root, game_sha)
    old = current_digest(pointer)
    if expected_current is not None and expected_current != old:
        raise ValueError("STALE_PROFILE_RESTORE")
    profile = load_snapshot(snapshots, digest, registry)
    if profile["game_sha256"] != game_sha:
        raise ValueError("SNAPSHOT_BELONGS_TO_DIFFERENT_GAME")
    if old is not None:
        existing = load_snapshot(snapshots, old, registry)
        if existing["game_sha256"] != game_sha:
            raise ValueError("EXISTING_PROFILE_WRONG_GAME")
    atomic_replace(pointer, encode({"schema":"kernix.game-pointer.v1","snapshot":digest}))
    return {"restored_snapshot":digest,"previous_snapshot":old,"game_sha256":game_sha}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--registry", default="components/registry.json")
    sub=ap.add_subparsers(dest="operation",required=True)
    s=sub.add_parser("save")
    s.add_argument("--profile", required=True)
    s.add_argument("--expected-current")
    r=sub.add_parser("restore")
    r.add_argument("--game-sha256", required=True)
    r.add_argument("--snapshot", required=True)
    r.add_argument("--expected-current")
    args=ap.parse_args()
    registry=read_json(args.registry)
    if args.operation=="save":
        result=save(args.root,read_json(args.profile),registry,args.expected_current)
    else:
        result=restore(args.root,args.game_sha256,args.snapshot,registry,args.expected_current)
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()
