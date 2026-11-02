#!/usr/bin/env python3
"""Collect official upstream version metadata; never install executable payloads.

Run on trusted CI with network. Output stable JSON; missing upstream data fails closed
and never replaces known-good catalog with an empty/partial result.
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = ROOT / "component-sources.json"
OUT = ROOT / "component-versions.json"
MAX_PAGES = 5  # 500 releases/tags at most per upstream (GitHub pagination)


def github_json(url):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RM11-WinCore-component-discovery",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=25) as response:
        return json.load(response)


def valid_tag(value):
    return isinstance(value, str) and 1 <= len(value) <= 110 and bool(
        re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+-]*", value)
    )


def get_versions(component):
    source = component["source"]
    upstream = component.get("upstream")
    if source == "manual_verified_packages":
        return []
    if source not in ("github_releases", "github_tags"):
        raise ValueError("unsupported component source")
    if not isinstance(upstream, str) or not re.fullmatch(
        r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", upstream
    ):
        raise ValueError("bad upstream repository")
    endpoint = "releases" if source == "github_releases" else "tags"
    collected = {}
    for page in range(1, MAX_PAGES + 1):
        url = f"https://api.github.com/repos/{upstream}/{endpoint}?per_page=100&page={page}"
        entries = github_json(url)
        if not isinstance(entries, list):
            raise ValueError("unexpected GitHub API output")
        for item in entries:
            if source == "github_releases" and (item.get("draft") or item.get("prerelease")):
                continue
            tag = item.get("tag_name") if source == "github_releases" else item.get("name")
            if not valid_tag(tag):
                continue
            # Don't trust download URLs from a release API as installable binaries.
            collected[tag] = {
                "tag": tag,
                "source_url": (
                    f"https://github.com/{upstream}/releases/tag/{tag}"
                    if source == "github_releases"
                    else f"https://github.com/{upstream}/tree/{tag}"
                ),
                "installable": False,
                "abi_verified": False,
                "runtime_tested": False,
                "reason": "Upstream source version; Android binary and compatibility NOT verified",
            }
        if len(entries) < 100:
            break
    return list(collected.values())



def wine_version_rank(tag):
    """Wine's GitHub tag API is not ordered by semantic version."""
    match = re.fullmatch(r"wine-(\d+)\.(\d+)(?:\.(\d+))?", tag)
    if not match:
        return (-1, -1, -1)
    return tuple(int(part or 0) for part in match.groups())


def observed_latest(component, versions):
    if not versions:
        return None
    if component["id"] == "wine" and component["source"] == "github_tags":
        candidates = [v["tag"] for v in versions if wine_version_rank(v["tag"])[0] >= 0]
        return max(candidates, key=wine_version_rank) if candidates else None
    return versions[0]["tag"]


def build_catalog(existing, config):
    old_by_id = {c["id"]: c for c in existing.get("components", [])}
    catalog = {"schema": 1, "policy": "Only signed/verified Android-compatible binaries may be installed; discovery never changes game profiles.", "components": []}
    for component in config["components"]:
        key = component["id"]
        previous = old_by_id.get(key, {})
        current = dict(component)
        if component["source"] == "manual_verified_packages":
            current["versions"] = previous.get("versions", [])
            current["note"] = "Turnip Android driver builds require source/WSI/ABI validation; not discoverable from Mesa release tags alone"
        else:
            latest = get_versions(component)
            # Keep previously observed versions, never silently drop old choices.
            saved = {v["tag"]: v for v in previous.get("versions", []) if valid_tag(v.get("tag"))}
            for item in latest:
                saved.setdefault(item["tag"], item)
            current["versions"] = list(saved.values())
            current["upstream_latest_seen"] = observed_latest(component, list(saved.values())) or previous.get("upstream_latest_seen")
            current["discovery_coverage"] = "partial_up_to_500_tags_or_releases; not an exhaustive historical archive"
        catalog["components"].append(current)
    return catalog


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = json.loads(SOURCES.read_text(encoding="utf-8"))
    existing = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    fresh = build_catalog(existing, config)
    rendered = json.dumps(fresh, ensure_ascii=False, indent=2) + "\n"
    if args.check:
        print("catalog validated: " + ", ".join(
            f"{c['id']}={len(c['versions'])}" for c in fresh["components"]
        ))
    else:
        OUT.write_text(rendered, encoding="utf-8")
        print("catalog updated; metadata only, NO binaries installed")


if __name__ == "__main__":
    main()
