#!/usr/bin/env python3
"""KERNIX offline Windows PE compatibility preflight. No executable is launched."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

MACHINES = {0x14c:"x86", 0x8664:"x86_64", 0xaa64:"arm64"}
SUBSYSTEMS = {2:"windows_gui", 3:"windows_console", 10:"efi_application"}
MAX_FILE = 2 * 1024 * 1024 * 1024

def inspect(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("FILE_MISSING_OR_TOO_LARGE")
    size = path.stat().st_size
    with path.open("rb") as fh:
        dos = fh.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("NOT_PE_DOS_HEADER")
        peoff = struct.unpack_from("<I",dos,0x3c)[0]
        if peoff < 64 or peoff > size-24:
            raise ValueError("INVALID_PE_OFFSET")
        fh.seek(peoff)
        head = fh.read(24)
        if head[:4] != b"PE\0\0":
            raise ValueError("NOT_PE_SIGNATURE")
        machine, sections, _, _, _, opt_size, flags = struct.unpack_from("<HHIIIHH",head,4)
        if sections == 0 or sections > 96 or peoff+24+opt_size > size:
            raise ValueError("INVALID_SECTION_TABLE")
        optional = fh.read(opt_size)
        if len(optional)<70:
            raise ValueError("TRUNCATED_OPTIONAL_HEADER")
        magic = struct.unpack_from("<H",optional)[0]
        if magic not in (0x10b,0x20b):
            raise ValueError("UNSUPPORTED_PE_OPTIONAL_MAGIC")
        subsystem = struct.unpack_from("<H",optional,68)[0]
        fh.seek(0)
        h=hashlib.sha256()
        while True:
            block=fh.read(1024*1024)
            if not block: break
            h.update(block)
    arch=MACHINES.get(machine, "unknown")
    hints=[]
    if arch=="unknown": hints.append("Unsupported or unrecognized CPU machine ID")
    if subsystem not in (2,3): hints.append("Nonstandard Windows application subsystem")
    return {
      "schema":"kernix.pe-static-preflight.v1",
      "file":path.name,"size_bytes":size,"sha256":h.hexdigest(),
      "machine_hex":f"0x{machine:04x}","architecture":arch,
      "pe_format":"PE32+" if magic==0x20b else "PE32",
      "subsystem":SUBSYSTEMS.get(subsystem,f"unknown_{subsystem}"),
      "sections":sections,
      "hints":hints,
      "runtime_tested":False,"fps_measured":False,
      "component_selection_verified":False,
      "note":"Static metadata is not enough to infer DirectX version, protected launchers, or game performance."
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe")
    p.add_argument("--output")
    args=p.parse_args()
    report=inspect(args.exe)
    result=json.dumps(report,indent=2,ensure_ascii=False)+"\n"
    if args.output: Path(args.output).write_text(result,encoding="utf-8")
    else: print(result,end="")

if __name__=="__main__":
    main()
