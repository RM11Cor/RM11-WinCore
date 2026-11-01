#!/usr/bin/env python3
"""Read-only, bounded PE import-table analyzer for KERNIX. Never executes game code."""
import argparse
import json
import struct
from pathlib import Path

GRAPHICS = {
    "d3d9.dll": "Direct3D 9",
    "d3d10.dll": "Direct3D 10",
    "d3d10_1.dll": "Direct3D 10.1",
    "d3d11.dll": "Direct3D 11",
    "d3d12.dll": "Direct3D 12",
    "dxgi.dll": "DXGI (version unspecified)",
    "vulkan-1.dll": "Vulkan loader",
    "opengl32.dll": "OpenGL",
    "ddraw.dll": "DirectDraw",
}
MAX_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORTS = 2048

def read_cstr(data, off, limit=260):
    if off < 0 or off >= len(data):
        raise ValueError("INVALID_IMPORT_STRING_OFFSET")
    end = data.find(b"\\0", off, min(len(data), off + limit))
    if end < 0:
        raise ValueError("UNTERMINATED_IMPORT_STRING")
    return data[off:end].decode("ascii", "replace")

def analyze(path):
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError("FILE_MISSING_OR_TOO_LARGE_FOR_IMPORT_SCAN")
    b = p.read_bytes()
    def u16(offset):
        if offset < 0 or offset+2 > len(b): raise ValueError("TRUNCATED_PE")
        return struct.unpack_from("<H", b, offset)[0]
    def u32(offset):
        if offset < 0 or offset+4 > len(b): raise ValueError("TRUNCATED_PE")
        return struct.unpack_from("<I", b, offset)[0]
    if len(b) < 64 or b[:2] != b"MZ": raise ValueError("INVALID_DOS_HEADER")
    pe = u32(0x3c)
    if pe < 64 or pe+24 > len(b) or b[pe:pe+4] != b"PE\\0\\0":
        raise ValueError("INVALID_PE_HEADER")
    sections = u16(pe+6)
    opt_size = u16(pe+20)
    opt = pe+24
    if not (1 <= sections <= MAX_SECTIONS) or opt+opt_size > len(b):
        raise ValueError("INVALID_SECTION_TABLE")
    magic = u16(opt)
    if magic == 0x10b: directory_start, min_optional = 96, 104
    elif magic == 0x20b: directory_start, min_optional = 112, 120
    else: raise ValueError("INVALID_OPTIONAL_MAGIC")
    if opt_size < min_optional: raise ValueError("IMPORT_DIRECTORY_UNAVAILABLE")
    import_rva, import_size = u32(opt+directory_start+8), u32(opt+directory_start+12)
    entries = []
    section_pos = opt+opt_size
    if section_pos + sections*40 > len(b): raise ValueError("TRUNCATED_SECTIONS")
    for i in range(sections):
        pos = section_pos + i*40
        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", b, pos+8)
        entries.append((virtual_addr, max(virtual_size, raw_size), raw_ptr, raw_size))
    headers_size = u32(opt+60) if opt_size >= 64 else 0
    def offset(rva, count=1):
        if rva < headers_size and rva+count <= len(b):
            return rva
        for addr, extent, raw, raw_size in entries:
            if addr <= rva and rva+count <= addr+extent:
                relative = rva-addr
                if relative+count <= raw_size and raw+relative+count <= len(b):
                    return raw+relative
        raise ValueError("UNMAPPED_IMPORT_RVA")
    names = []
    if import_rva and import_size:
        for i in range(min(MAX_IMPORTS, import_size // 20)):
            off = offset(import_rva + i*20, 20)
            descriptor = struct.unpack_from("<IIIII", b, off)
            if descriptor == (0,0,0,0,0): break
            name = read_cstr(b, offset(descriptor[3]))
            if name: names.append(name.lower())
        else:
            raise ValueError("IMPORT_DESCRIPTOR_LIMIT_OR_UNTERMINATED")
    graphics = sorted({GRAPHICS[n] for n in names if n in GRAPHICS})
    return {
        "schema":"kernix.pe-import-audit.v1",
        "file":p.name,
        "static_imports":sorted(set(names)),
        "graphics_api_indicators":graphics,
        "observed_api_only":True,
        "dynamic_imports_not_detected":True,
        "recommendation":"No component selection without full compatibility registry and runtime evidence",
        "note":"Import list can omit APIs loaded at runtime; DXGI alone does not identify D3D version."
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe")
    parser.add_argument("--output")
    a=parser.parse_args()
    result=json.dumps(analyze(a.exe),indent=2,ensure_ascii=False)+"\\n"
    if a.output: Path(a.output).write_text(result,encoding="utf-8")
    else: print(result,end="")

if __name__=="__main__": main()
