#!/usr/bin/env python3
"""FH5 M27: extract only four compiled paint/glass DXIL stages from the user's own archive.
Keeps a verified local shader ZIP cache. Does not execute game or shader binaries.
"""
from pathlib import Path
import getpass, hashlib, json, shutil, zipfile, struct

OUTER = "Forza Horizon 5/media/_library/Shaders.zip"
SHA = "f63adaf172e828059ac3b2416b9dbae800d52b1f05406f30a28cbe33cd416452"
SIZE = 120167930
CACHE = Path("/sdcard/Download/FH5_M27_Cache/Shaders.zip")
RESULT = Path("/sdcard/Download/FH5_M27_DXIL_EVIDENCE.zip")
FAMILIES = ("traffic_vehicle_paint", "traffic_vehicle_glass")
STAGES = ("pso", "vso")
TARGETS = {
    f"{family}.{stage}":
    f"pg_trafficvehicles/{family}/{family}CarLightScenario.pcdxil.{stage}"
    for family in FAMILIES for stage in STAGES
}

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_cache():
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    if CACHE.exists():
        if CACHE.stat().st_size == SIZE and digest(CACHE) == SHA:
            print("VERIFIED CACHE; downloading 0 bytes:", CACHE)
            return
        raise ValueError("Cached Shaders.zip has unexpected size or hash. Rename manually; no overwrite.")
    try:
        from remotezip import RemoteZip
    except ImportError as exc:
        raise RuntimeError("Enter Ubuntu and install: python3 -m pip install --break-system-packages remotezip") from exc
    url = getpass.getpass("Paste original FH5 ZIP link (input hidden): ").strip()
    if not url.startswith("https://"):
        raise ValueError("An HTTPS URL is required")
    part = CACHE.with_suffix(".zip.part")
    h = hashlib.sha256()
    count = 0
    try:
        with RemoteZip(url) as remote:
            matches = [i for i in remote.infolist() if i.filename.lower() == OUTER.lower()]
            if len(matches) != 1:
                raise ValueError("Expected one global Shaders.zip member")
            info = matches[0]
            if info.file_size != SIZE or info.compress_size > 135 * 1024 * 1024:
                raise ValueError("Archive size differs from verified M26 source")
            if shutil.disk_usage(CACHE.parent).free < SIZE + 70 * 1024 * 1024:
                raise OSError("Need approximately 190 MB of available storage")
            print("Transferring only global Shaders.zip; expected packed bytes:", info.compress_size)
            with remote.open(info.filename) as source, part.open("wb") as out:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > SIZE:
                        raise ValueError("Unexpected download length")
                    h.update(chunk)
                    out.write(chunk)
        if count != SIZE or h.hexdigest() != SHA:
            raise ValueError("SHA-256 mismatch; download not accepted")
        part.replace(CACHE)
    finally:
        part.unlink(missing_ok=True)
    print("Archive checksum verified; cache retained:", CACHE)

def probe(data):
    records = []
    start = 0
    for _ in range(8):
        offset = data.find(b"DXBC", start)
        if offset < 0:
            break
        item = {"offset": offset, "status": "UNVERIFIED"}
        if offset + 32 <= len(data):
            size, count = struct.unpack_from("<II", data, offset + 24)
            item["declared_bytes"], item["chunks"] = size, count
            if 32 <= size <= len(data) - offset and 0 < count <= 128 and 32 + 4 * count <= size:
                valid = True
                for n in range(count):
                    pos = struct.unpack_from("<I", data, offset + 32 + 4 * n)[0]
                    if pos > size - 8 or offset + pos + 8 > len(data):
                        valid = False
                        break
                    length = struct.unpack_from("<I", data, offset + pos + 4)[0]
                    if length > size - pos - 8:
                        valid = False
                        break
                item["status"] = "BOUNDS_OK" if valid else "BAD_CHUNK_BOUNDS"
        records.append(item)
        start = offset + 4
    return {"prefix_hex": data[:48].hex(), "dxbc_matches": records,
            "dxil_tags": data.count(b"DXIL"),
            "note": "This only checks container bounds; shader semantics remain unknown."}

def main():
    ensure_cache()
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    report = {"stage": "M27", "source": OUTER, "archive_sha256": SHA,
              "targets": [], "successes": 0}
    with zipfile.ZipFile(CACHE) as archive, zipfile.ZipFile(RESULT, "w", zipfile.ZIP_DEFLATED) as output:
        names = {}
        for info in archive.infolist():
            names.setdefault(info.filename.replace("\\", "/").lower(), []).append(info)
        report["inner_zip_entries"] = sum(map(len, names.values()))
        for key, path in TARGETS.items():
            matches = names.get(path.lower(), [])
            entry = {"key": key, "expected_path": path, "matches": len(matches)}
            if len(matches) == 1 and 0 < matches[0].file_size <= 2 * 1024 * 1024:
                file_info = matches[0]
                data = archive.read(file_info)
                entry.update(status="EXTRACTED", bytes=len(data),
                             sha256=hashlib.sha256(data).hexdigest(),
                             container_probe=probe(data))
                output.writestr("dxil_samples/" + key.replace(".", "_") + ".pcdxil." + key.split(".")[-1], data)
                report["successes"] += 1
            else:
                entry["status"] = ("NOT_FOUND" if not matches else
                                   "DUPLICATE" if len(matches) > 1 else "SKIPPED_SIZE")
            report["targets"].append(entry)
            print(key, entry["status"], entry.get("bytes", ""))
        report["status"] = "COMPLETE" if report["successes"] == 4 else "PARTIAL"
        output.writestr("M27_DXIL_REPORT.json", json.dumps(report, indent=2))
    print("SAVED:", RESULT)
    print("FILES:", report["successes"], "/4")
    print("CACHE RETAINED:", CACHE)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("M27 ERROR:", type(exc).__name__ + ":", exc)
        raise SystemExit(2)
