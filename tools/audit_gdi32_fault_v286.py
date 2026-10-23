#!/usr/bin/env python3
"""Static audit of exact gdi32.dll from pinned RM11 v2.8.5 release.
Crash report from embedded MessageBox test:
  read violation: 00000000000002AE
  gdi32.dll + 0x772D4
  user32.dll + 0xB6090, +0xB78A4
Does NOT claim to symbolicate private Wine functions without debug symbols.
"""
import hashlib
import io
import re
import struct
import zipfile
from pathlib import Path

APK=Path("audit/app-release.apk")
RVA=0x772d4

def h(b):return hashlib.sha256(b).hexdigest()

with zipfile.ZipFile(APK) as app:
    nested=app.read("assets/runtime/rm11-wine-stack.zip")
    with zipfile.ZipFile(io.BytesIO(nested)) as runtime:
        names=[x for x in runtime.namelist() if x=="lib/wine/aarch64-windows/gdi32.dll"]
        assert len(names)==1,(names)
        name=names[0]
        dll=runtime.read(name)
        assert dll[:2]==b'MZ'
        pe=struct.unpack_from("<I",dll,0x3c)[0]
        assert dll[pe:pe+4]==b"PE\0\0"
        machine=struct.unpack_from("<H",dll,pe+4)[0]
        opt=pe+24
        magic=struct.unpack_from("<H",dll,opt)[0]
        assert magic==0x20b,hex(magic)
        section_count=struct.unpack_from("<H",dll,pe+6)[0]
        table=opt+struct.unpack_from("<H",dll,pe+20)[0]
        sections=[]
        for i in range(section_count):
            s=table+i*40
            section=dll[s:s+8].rstrip(b'\0').decode('ascii','replace')
            vsize,virt,rawsize,raw=struct.unpack_from('<IIII',dll,s+8)
            sections.append((section,virt,vsize,rawsize,raw))
        section=next((s for s in sections if s[1]<=RVA<s[1]+max(s[2],s[3])),None)
        assert section is not None,"Crash offset does not map into PE sections"
        off=section[4]+RVA-section[1]
        assert off+4<=len(dll)
        print("RM11_GDI32_PE64_CRASH_RVA_AUDIT_V286")
        print("Source pinned RM11 v2.8.5 signed APK, NOT an arbitrary Wine version")
        print("gdi32 archive path:",name)
        print("gdi32 bytes:",len(dll),"SHA256:",h(dll))
        print("PE machine:",hex(machine),"PE optional header:",hex(magic))
        print("fault RCA RVA:",hex(RVA),"section:",section[0],"PE raw offset:",hex(off))
        print("section table:",sections)
        print("fault code bytes:",dll[off:off+32].hex(' '))
        print("fault address low null read 0x2AE: human observed; not proven by bytes alone")
        blob=Path("audit/gdi32.dll")
        blob.write_bytes(dll)
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            if machine not in (0xaa64,0xa641):
                print("DISASSEMBLY_NOT_SAFE: non ARM64 PE machine")
            else:
                md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
                md.detail=False
                begin=(RVA-0x80)&~3
                foff=section[4]+begin-section[1]
                md.skipdata=True
                for ins in md.disasm(dll[foff:foff+0x110],begin):
                    flag=">>> FAULT_RVA" if ins.address==RVA else ""
                    print(f"  {ins.address:08X}  {ins.mnemonic:<9} {ins.op_str:<52} {flag}")
                print("== Fault instruction decoding from its exact RVA ==")
                fault=list(md.disasm(dll[off:off+24],RVA))
                assert fault and fault[0].address==RVA
                print("EXACT_FAULT_RVA_INSTRUCTION",fault[0].mnemonic,fault[0].op_str)
        except ImportError:
            print("capstone unavailable; raw PE data emitted")
        # Link into the native debugger next, not a hard-coded guessed patch.
        report=Path("audit/gdi32-crash-rva.txt")
        report.write_text("gdi32: "+name+"\nSHA256 "+h(dll)+"\nMachine "+hex(machine)
                           +"\nFault RVA "+hex(RVA)+"\nSection "+section[0]
                           +"\nFault code bytes "+dll[off:off+32].hex(" ")+"\n")
