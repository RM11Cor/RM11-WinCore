#!/usr/bin/env python3
"""Fail-closed static audit of duplicate original IFUNC ARM64 native workflow stages.

This is SOURCE-ONLY CI hygiene, NOT an attestation of real FEX hardware or games.
It protects an expensive ARM64 workflow from accidental repeated per-IFUNC
hardware traps/exports during parallel development.
"""
from collections import Counter
from pathlib import Path
import re
import sys

WORKFLOW = ".github/workflows/kernix-g0-original-ldso-self-irelative-after-real-main-seal-hw-access-arm64.yml"
STAGES = (
    ("source", "Fetch independently source-audited GNU libc IFUNC"),
    ("writer", "Observe distinct original IFUNC"),
    ("ret_source", "Download independently source-preflighted IFUNC"),
    ("ret_native", "Monitor genuine IFUNC"),
)

def gate(root: Path):
    workflow = root / WORKFLOW
    assert workflow.is_file() and not workflow.is_symlink()
    data = workflow.read_text()
    lines = data.splitlines()
    counts = Counter()
    sequence = {}
    for n, line in enumerate(lines, 1):
        if not line.startswith("      - name: "):
            continue
        title = line.removeprefix("      - name: ")
        for stage, prefix in STAGES:
            if not title.startswith(prefix):
                continue
            tail = title[len(prefix):]
            m = re.match(r"([0-9]+)\b", tail)
            assert m is not None, (n, title)
            index = int(m.group(1))
            assert 102 <= index <= 146, (n, title)
            key = (index, stage)
            counts[key] += 1
            assert counts[key] == 1, ("duplicate native hardware workflow stage", key, n)
            sequence[key] = n
    assert counts, "no source-pinned native hardware stages found"
    for idx in {x[0] for x in counts}:
        if (idx, "writer") in sequence:
            assert (idx, "source") in sequence
            assert sequence[idx, "source"] < sequence[idx, "writer"]
        if (idx, "ret_native") in sequence:
            assert (idx, "ret_source") in sequence
            assert sequence[idx, "ret_source"] < sequence[idx, "ret_native"]
            if (idx, "writer") in sequence:
                assert sequence[idx, "writer"] < sequence[idx, "ret_native"]
    marker = "      - uses: actions/upload-artifact@v4\n        if: always()"
    assert data.count(marker) == 1, "exactly one final ARM64 evidence upload expected"
    upload = data.split(marker, 1)[1]
    assert "\n          path: |\n" in upload
    artifact_lines = re.findall(r"^            (dist/[^\s]+)$", upload, re.M)
    artifact_counts = Counter(artifact_lines)
    assert artifact_lines and len(artifact_lines) >= 80
    # These two IFUNC103 source-plan lines predate per-stage proof receipts.
    # They are duplicated upload *names* only, not repeated native execution.
    # Keep a narrowly scoped grandfathered exception; reject any new duplicates.
    legacy_source_plan_only = {
        "dist/original-libc-IFUNC103-original-one-FEX-CALL-C3-RET-native-HW-read-source-plan.json",
        "dist/original-libc-IFUNC103-original-one-FEX-CALL-C3-RET-native-HW-read-and-GNU-writer.gdb",
    }
    duplicates = {p for p, n in artifact_counts.items() if n > 1}
    assert duplicates <= legacy_source_plan_only, ("duplicate uploaded native hardware evidence paths", sorted(duplicates))
    assert all(artifact_counts[p] <= 2 for p in duplicates)
    assert all("IFUNC103" in p and "real-FEX-native-HW-WRITE-only" not in p for p in duplicates)
    for index, stage in counts:
        if stage != "writer":
            continue
        suffix = f"original-libc-IFUNC{index}-real-FEX-native-HW-WRITE-only"
        for ext in (".log", ".exit"):
            need = "dist/" + suffix + ext
            if index >= 108:
                # One exact path OR one lossless IFUNC-index-scoped archive glob.
                # Reject both together (double coverage), missing data, and any
                # wildcard that might consume a neighboring IFUNC index.
                index_scoped_glob = f"dist/original-libc-IFUNC{index}-*"
                coverage = artifact_counts[need] + artifact_counts[index_scoped_glob]
                assert coverage == 1, (
                    "writer missing or duplicated original log/exit archive",
                    index, need, coverage
                )
    print("KERNIX_G0_ONE_NATIVE_IFUNC_STAGE_PER_INDEX_AND_UNIQUE_EVIDENCE_ARTIFACT_PATHS_PASS")
    print("stage_count", len(sequence), "stage_indices", sorted({idx for idx, _ in sequence}))
    print("unique_artifact_paths", len(artifact_counts))

if __name__ == "__main__":
    assert len(sys.argv) == 2
    gate(Path(sys.argv[1]))
