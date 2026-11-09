#!/usr/bin/env python3
"""Read the 147 ORIGINAL libc RELA/JMPREL source records without executing any guest code.

This intentionally produces candidate locations, NOT new verified real FEX writers,
not symbol-resolution proof, and never an Android compatibility claim.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys


PINNED_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LIBC_BIAS = 0x804000000


def make_inventory(libc):
    assert len(libc) == 2118168
    assert hashlib.sha256(libc).hexdigest() == PINNED_SHA
    assert libc[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<H", libc, 18)[0] == 62
    ph_off = struct.unpack_from("<Q", libc, 32)[0]
    ph_ent, ph_count = struct.unpack_from("<HH", libc, 54)
    assert ph_ent == 56 and 0 < ph_count <= 128
    assert ph_off + ph_count * ph_ent <= len(libc)
    ph = [struct.unpack_from("<IIQQQQQQ", libc, ph_off + i * ph_ent)
          for i in range(ph_count)]
    load = [p for p in ph if p[0] == 1]
    assert load and all(p[5] <= p[6] and p[2] + p[5] <= len(libc)
                        for p in load)
    dyn = [p for p in ph if p[0] == 2]
    assert len(dyn) == 1 and dyn[0][5] % 16 == 0
    assert dyn[0][2] + dyn[0][5] <= len(libc)

    def file_offset(va, n, *, rw_nx=False):
        matches = [p for p in load
                   if p[3] <= va and n >= 0 and va + n <= p[3] + p[5]
                   and (not rw_nx or ((p[1] & 6) == 6 and not (p[1] & 1)))]
        assert len(matches) == 1, (hex(va), n)
        return matches[0][2] + va - matches[0][3]

    tags = {}
    for pos in range(dyn[0][2], dyn[0][2] + dyn[0][5], 16):
        tag, val = struct.unpack_from("<qQ", libc, pos)
        if tag == 0:
            break
        if tag in (7, 8, 9, 23, 2, 20):
            assert tag not in tags
            tags[tag] = val
    assert set(tags) == {7, 8, 9, 23, 2, 20}
    assert tags[8] == 86 * 24
    assert tags[2] == 61 * 24
    assert tags[9] == 24 and tags[20] == 7
    assert tags[7] != 0 and tags[23] != 0

    records = []
    for group, va, count in (("DT_RELA", tags[7], 86),
                             ("DT_JMPREL", tags[23], 61)):
        pos = file_offset(va, count * 24)
        for i in range(count):
            offset, info, addend = struct.unpack_from("<QQq", libc, pos + 24 * i)
            kind = info & 0xffffffff
            symbol = info >> 32
            assert offset % 8 == 0 and 0x1ff000 <= offset < 0x211000
            src_offset = file_offset(offset, 8, rw_nx=True)
            initial = struct.unpack_from("<Q", libc, src_offset)[0]
            if kind == 37:
                assert symbol == 0  # ELF x86_64 R_X86_64_IRELATIVE
            records.append({
                "index": len(records),
                "table": group,
                "table_index": i,
                "r_offset": hex(offset),
                "source_guest_target": hex(LIBC_BIAS + offset),
                "r_type": kind,
                "r_sym": symbol,
                "r_addend": addend,
                "source_qword": hex(initial),
            })

    assert len(records) == 147
    assert sum(r["r_type"] == 37 for r in records) == 46
    assert len({r["r_offset"] for r in records}) == 147
    first = records[86]
    assert (first["table"], first["r_type"], first["r_sym"],
            first["r_offset"], first["source_qword"]) == (
            "DT_JMPREL", 7, 1604, "0x202ba0", "0x28020")
    # All next candidates remain hypotheses until a new genuine hardware
    # write trace shows real original GNU guest RIP and native store.
    next_candidates = [r for r in records[87:]
                       if r["table"] == "DT_JMPREL" and r["r_type"] == 7
                       and r["r_sym"] > 0 and int(r["source_qword"], 16) != 0]
    candidate_indices = [r["index"] for r in next_candidates]
    assert candidate_indices == sorted(set(candidate_indices))
    assert all(87 <= i <= 146 for i in candidate_indices)
    # Tamper guards for summary logic: duplicate, missing or wrong order
    # cannot pass original contiguous source table inventories.
    def valid(rows):
        return (len(rows) == 147
                and [x["index"] for x in rows] == list(range(147))
                and len({x["r_offset"] for x in rows}) == 147
                and sum(x["r_type"] == 37 for x in rows) == 46)
    assert valid(records)
    assert not valid(records[:-1])
    assert not valid(records + [records[0]])
    assert not valid(records[::-1])
    assert not valid(records[:1] + [{**records[1], "r_offset": records[0]["r_offset"]}] + records[2:])
    return {
        "schema": "kernix.g0.original-libc-147-rela-jmprel-source-inventory.v1",
        "libc_source_sha256": PINNED_SHA,
        "original_DT_RELA_count": 86,
        "original_DT_JMPREL_count": 61,
        "original_R_X86_64_IRELATIVE_count": 46,
        "original_non_IRELATIVE_count": 101,
        "all_original_targets_file_backed_RW_NX": True,
        "unique_original_target_count": 147,
        "first_actual_hw_observed_source_record": 86,
        "first_actual_hw_observation_source": "Linux ARM64 real FEX CI 42654919201; independent replay pending",
        "next_source_candidates": next_candidates,
        "next_source_candidate_indices": candidate_indices,
        "next_source_candidate_count": len(next_candidates),
        "new_native_hw_writer_observed_by_this_job": False,
        "all_original_rela_jmprel_writers_proven": False,
        "IFUNC_resolvers_executed_by_this_job": False,
        "Android_Wine_Proton_games_proven": False,
        "negative_source_record_mutations_rejected": True,
    }


if __name__ == "__main__":
    assert len(sys.argv) == 2
    dist = Path(sys.argv[1])
    src = dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    assert src.is_file() and not src.is_symlink()
    record = make_inventory(src.read_bytes())
    out = dist / "original-libc-147-rela-jmprel-source-inventory.json"
    out.write_text(json.dumps(record, indent=2) + "\n")
    print("KERNIX_G0_SOURCE_ONLY_LIBC_147_RELA_JMPREL_46_IFUNC_INVENTORY_PASS_NO_NEW_GUEST_WRITER")
