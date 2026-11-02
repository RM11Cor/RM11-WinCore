#!/usr/bin/env python3
"""Fail-closed KERNIX clean-branch manifest gate. Read-only; no Android execution."""
import json
import subprocess
import sys
from pathlib import Path

EXPECTED_FILES = {
    ".github/workflows/kernix-build-proven-upstream-317.yml",
    ".github/workflows/kernix-build-isolated-identity.yml",
    ".github/workflows/kernix-publish-direct-apk.yml",
    ".github/workflows/kernix-upstream-engine-baseline.yml",
    ".gitmodules",
    "README.md",
    "engines/README.md",
    "engines/backend-source-lock.json",
    "engines/bannerlator_3_1_7",
    "tools/verify_kernix_upstream_stack.py",
    "tools/verify_clean_engine_tree.py",
    "tools/audit_android_identity.py",
    "tools/kernix_game_preflight.py",
    "tools/test_kernix_game_preflight.py",
    "tools/kernix_pe_imports.py",
    "tools/test_kernix_pe_imports.py",
    "tools/kernix_component_registry.py",
    "tools/test_kernix_component_registry.py",
    "tools/kernix_game_profiles.py",
    "tools/test_kernix_game_profiles.py",
    "tools/kernix_profile_store.py",
    "tools/test_kernix_profile_store.py",
    "tools/kernix_integrated_game_report.py",
    "tools/test_kernix_integrated_game_report.py",
    "tools/kernix_benchmark_evidence.py",
    "tools/test_kernix_benchmark_evidence.py",
    "tools/kernix_frame_log_import.py",
    "tools/test_kernix_frame_log_import.py",
    "tools/kernix_performance_evidence_bundle.py",
    "tools/test_kernix_performance_evidence_bundle.py",
    "tools/kernix_display_session_summary.py",
    "tools/test_kernix_display_session_summary.py",
    "android-bridge/KernixDiagnosticsActivity.java",
    "android-bridge/KernixDisplaySessionObserver.java",
    "tools/patch_kernix_android_diagnostics.py",
    "components/registry.json",
}
EXPECTED_SHA = "146158413f25e28f9ad04d921d0b7b806f86cc53"

def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()

def main():
    root = Path(__file__).resolve().parents[1]
    import os
    os.chdir(root)
    tracked = set(git("ls-files", "-z").split("\0")) - {""}
    unexpected = sorted(tracked - EXPECTED_FILES)
    missing = sorted(EXPECTED_FILES - tracked)
    if unexpected or missing:
        raise SystemExit(f"CLEAN_ENGINE_TREE_FAIL unexpected={unexpected} missing={missing}")
    if git("ls-files", "--stage", "--", "engines/bannerlator_3_1_7").split()[0] != "160000":
        raise SystemExit("CLEAN_ENGINE_TREE_FAIL submodule_mode")
    if git("rev-parse", "HEAD:engines/bannerlator_3_1_7") != EXPECTED_SHA:
        raise SystemExit("CLEAN_ENGINE_TREE_FAIL submodule_commit")
    lock = json.loads((root / "engines/backend-source-lock.json").read_text())
    if lock["source_sha"] != EXPECTED_SHA or lock["packaged_in_kernix_apk"] is not False:
        raise SystemExit("CLEAN_ENGINE_TREE_FAIL lock_or_packaging_claim")
    for path in sorted(p for p in tracked if p.startswith(".github/workflows/")):
        body = (root / path).read_text()
        if "kernix-next-clean-engine" not in body:
            raise SystemExit(f"CLEAN_ENGINE_TREE_FAIL wrong_ci_branch: {path}")
    print("KERNIX_CLEAN_ENGINE_TREE_PASS", len(tracked), "tracked paths; zero legacy workflows")

if __name__ == "__main__":
    main()
