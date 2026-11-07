#!/usr/bin/env python3
"""Fail-closed source-only original x86_64 main PLT JUMP_SLOT inventory.

Read only the SHA256-locked original ELF. Does not prove that the genuine
guest loader wrote the GOT, resolved the symbol or executed original main.
"""
import hashlib
import json
import re
import struct
from pathlib import Path

ORIGINAL_MAIN = Path("dist/original-source-pinned-root/bin/kernix-g2e-dynamic-guest")
EXPECTED_SHA = "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
OUT = Path("dist/original-main-plt-jumpslot-source-inventory.json")

def require(condition, reason):
    if not condition:
        raise AssertionError(reason)

def inspect_source(data):
    require(len(data) == 15976 and hashlib.sha256(data).hexdigest() == EXPECTED_SHA,
            "source original main SHA256/length mismatch")
    require(data[:6] == bytes.fromhex("7f454c460201")
            and struct.unpack_from("<H", data, 18)[0] == 62,
            "not original x86-64 little-endian ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    require(phsize == 56 and 1 <= phnum <= 64
            and phoff + phsize * phnum <= len(data), "invalid source program headers")
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56)
             for i in range(phnum)]
    loads = [p for p in phdrs if p[0] == 1]
    dynamics = [p for p in phdrs if p[0] == 2]
    require(len(loads) >= 2 and len(dynamics) == 1,
            "original source PT_LOAD/PT_DYNAMIC missing")
    def file_offset(vma, amount):
        hits = [p[2] + vma - p[3] for p in loads
                if amount > 0 and vma >= p[3]
                and vma - p[3] + amount <= p[5]
                and p[2] <= len(data) and p[5] <= len(data) - p[2]]
        require(len(hits) == 1, "source VMA file mapping absent/ambiguous")
        return hits[0]
    dyn = dynamics[0]
    require(dyn[5] % 16 == 0 and dyn[2] + dyn[5] <= len(data),
            "original PT_DYNAMIC file bounds changed")
    tags = {}
    terminated = False
    for pos in range(dyn[2], dyn[2] + dyn[5], 16):
        tag, value = struct.unpack_from("<qQ", data, pos)
        if tag == 0:
            terminated = True
            break
        if tag in (2, 5, 6, 7, 8, 9, 10, 11, 20, 23, 24, 30, 0x6ffffffb):
            require(tag not in tags, "duplicate original ELF dynamic tag")
            tags[tag] = value
    require(terminated and all(k in tags for k in (2, 5, 6, 7, 8, 9, 10, 11, 20, 23)),
            "original DT_JMPREL / DT_RELA metadata missing")
    require(tags[8] == 192 and tags[9] == 24 and tags[11] == 24
            and 0 < tags[10] <= 8192, "original dynamic symbol/main RELA sizes changed")
    require(tags[20] == 7 and tags[2] == 24,
            "original DT_PLTREL is not RELA or expected one PLT relocation")
    # DT_FLAGS bit 0x8 and DT_FLAGS_1 bit 0x1 indicate eager binding;
    # DT_BIND_NOW (24) may also be present as a tag. These are SOURCE
    # attributes only, not a claim about runtime ld-linux state.
    source_bind_now = (24 in tags or bool(tags.get(30, 0) & 0x8)
                       or bool(tags.get(0x6ffffffb, 0) & 0x1))
    offset = file_offset(tags[23], tags[2])
    target, info, addend = struct.unpack_from("<QQq", data, offset)
    reloc_type = info & 0xffffffff
    symbol_index = info >> 32
    require(reloc_type == 7 and 0 < symbol_index < 65536,
            "original PLT relocation is not one R_X86_64_JUMP_SLOT")
    symoff = file_offset(tags[6] + symbol_index * 24, 24)
    nameoff, st_info, st_other, shndx, value, size = struct.unpack_from(
        "<IBBHQQ", data, symoff)
    str_off = file_offset(tags[5], tags[10])
    strings = data[str_off:str_off + tags[10]]
    require(0 < nameoff < len(strings), "original imported symbol name missing")
    end = strings.find(b"\0", nameoff)
    require(nameoff < end and end - nameoff <= 96,
            "original imported symbol name not terminated")
    name = strings[nameoff:end].decode("ascii")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.@]*", name)
            and name == "puts", "original main JUMP_SLOT import is not puts")
    require((st_info >> 4) == 1 and shndx == 0 and value == 0,
            "original JUMP_SLOT is not undefined globally bound import")
    require((st_info & 15) in (0, 2), "original puts symbol is not FUNC/NOTYPE")
    # The .got/.got.plt target must belong to original writable main
    # PT_LOAD. Its initial source bytes can contain a PLT trampoline pointer.
    writable = [p for p in loads if (p[1] & 2) and p[3] <= target
                and target - p[3] + 8 <= p[6]]
    require(len(writable) == 1, "original JUMP_SLOT target not in one RW PT_LOAD")
    # The target might be BSS/non-file backed; record this transparently.
    initial_offsets = [p[2] + target - p[3] for p in writable
                       if target - p[3] + 8 <= p[5]
                       and p[2] + p[5] <= len(data)]
    initial = (struct.unpack_from("<Q", data, initial_offsets[0])[0]
               if len(initial_offsets) == 1 else None)
    return {
        "schema": "kernix.g0.original-main-plt-jumpslot-source-only.v1",
        "source_main_SHA256": EXPECTED_SHA,
        "source_DT_RELA_main_entries": 8,
        "source_DT_JMPREL_entries": 1,
        "source_DT_PLTREL_is_RELA": True,
        "source_JUMP_SLOT_symbol": name,
        "source_symbol_index": symbol_index,
        "source_symbol_binding": "STB_GLOBAL",
        "source_symbol_definition": "SHN_UNDEF",
        "source_JUMP_SLOT_relocation_offset": hex(target),
        "source_JUMP_SLOT_guest_target": hex(0x800000000 + target),
        "source_JUMP_SLOT_addend": addend,
        "source_file_backed_GOT_initial": hex(initial) if initial is not None else None,
        "source_bind_now_requested": source_bind_now,
        "loader_got_write_or_plt_lazy_binding_proven": False,
        "loader_puts_symbol_resolution_and_version_proven": False,
        "exact_original_guest_writer_RIP_proven": False,
        "all_original_main_relocations_proven": False,
        "original_main_RELRO_sealed": False,
        "android_bionic_or_gameplay_proven": False,
    }

def run():
    report = inspect_source(ORIGINAL_MAIN.read_bytes())
    require(report["source_JUMP_SLOT_symbol"] == "puts"
            and report["source_DT_JMPREL_entries"] == 1
            and report["loader_got_write_or_plt_lazy_binding_proven"] is False
            and report["original_main_RELRO_sealed"] is False,
            "source-only result promoted to runtime proof")
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print("KERNIX_G0_ORIGINAL_PUTS_JUMP_SLOT_SOURCE_SHA256_INVENTORY_ONLY_PASS")
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    run()
