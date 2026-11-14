#!/usr/bin/env python3
"""Strict native Windows x64 PE fixture validation; no execution assumed."""
from pathlib import Path
import struct,sys,json,hashlib

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]

def analyze(path):
    b=Path(path).read_bytes()
    assert len(b)>4096 and b[:2]==b"MZ", "MZ_INVALID"
    pos=u32(b,0x3c)
    assert 64<=pos<len(b)-256 and b[pos:pos+4]==b"PE\0\0", "PE_SIGNATURE_INVALID"
    machine=u16(b,pos+4)
    section_count=u16(b,pos+6)
    size_opt=u16(b,pos+20)
    opt=pos+24
    assert machine==0x8664,"NOT_PE64_AMD64"
    assert 1<=section_count<=96 and size_opt>=128 and opt+size_opt<=len(b),"COFF_CORRUPT"
    assert u16(b,opt)==0x20b,"NOT_PE32_PLUS"
    assert (u16(b,pos+22)&0x2000)==0,"DLL_NOT_EXE" # IMAGE_FILE_DLL
    assert (u16(b,pos+22)&0x0002)!=0,"IMAGE_NOT_EXECUTABLE"
    subsys=u16(b,opt+68)
    assert subsys==3,"NOT_CONSOLE_WINDOWS_SUBSYSTEM"
    n_dirs=u32(b,opt+108)
    assert n_dirs>=2,"NO_IMPORT_DIRECTORY"
    imp_rva=u32(b,opt+120) # PE32+ data directory index 1
    assert imp_rva,"NO_IMPORTS"
    secs=[]
    for i in range(section_count):
        off=opt+size_opt+i*40
        assert off+40<=len(b),"SECTION_TABLE_OUT_OF_BOUNDS"
        vs=u32(b,off+8); va=u32(b,off+12)
        raw_size=u32(b,off+16); raw=u32(b,off+20)
        assert raw+raw_size<=len(b),"RAW_SECTION_OOB"
        secs.append((va,max(vs,raw_size),raw,raw_size))
    def map_rva(rva):
        for va,size,raw,raw_size in secs:
            if va<=rva<va+size:
                delta=rva-va
                assert delta<raw_size and raw+delta<len(b),"UNBACKED_RVA"
                return raw+delta
        raise AssertionError("RVA_NOT_MAPPED")
    def cstr(offset):
        assert 0<=offset<len(b),"STRING_OFFSET_OOB"
        end=b.find(b"\0",offset,min(len(b),offset+256))
        assert end>offset,"BAD_STRING"
        return b[offset:end].decode("ascii")
    imports=[]
    ip=map_rva(imp_rva)
    for i in range(128):
        at=ip+i*20
        assert at+20<=len(b),"IMPORT_DESC_OOB"
        d=struct.unpack_from("<IIIII",b,at)
        if d==(0,0,0,0,0): break
        assert d[3] and d[4],"BAD_IMPORT_DESCRIPTOR"
        imports.append(cstr(map_rva(d[3])))
    else:
        raise AssertionError("IMPORTS_NOT_TERMINATED")
    assert any(x.lower()=="kernel32.dll" for x in imports),("MISSING_KERNEL32_IMPORT",imports)
    for api in [b"GetCurrentThreadId",b"GetCurrentProcessId",b"VirtualAlloc",b"VirtualProtect",
                b"VirtualFree",b"TlsAlloc",b"TlsSetValue",b"TlsGetValue",b"TlsFree",
                b"WriteFile",b"GetStdHandle"]:
        assert api in b,("MISSING_IMPORT_TOKEN",api)
    return {
        "schema":"r4.carx.r3c16.win64-real-pe-console-fixture.v1",
        "source":"r3c16/win64_vmem_tls_stdout_smoke.c",
        "sha256":hashlib.sha256(b).hexdigest(),
        "pe_machine":"AMD64",
        "pe_optional_header_magic":"PE32+",
        "windows_subsystem":"CONSOLE",
        "imported_dlls":sorted(set(imports)),
        "win64_kernel32_imports_structurally_verified":True,
        "guest_x86_64_windows_api_executed":False,
        "wine_android_runtime_executed":False,
        "carx_game_executed":False,
        "graphics_triangle_rendered":False
    }

if __name__=="__main__":
    d=analyze(sys.argv[1])
    Path(sys.argv[2]).write_text(json.dumps(d,indent=2)+"\n")
    print("CARX_R3C16_REAL_WIN64_PE64_FIXTURE_STRUCTURAL_PASS",d["sha256"])
