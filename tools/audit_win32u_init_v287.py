#!/usr/bin/env python3
"""Offline binary-ABI audit of a pinned, signed RM11 v2.8.5 Wine build.

This is a structural audit, not a proof that Wine actually called init_user().
The fault at gdi32 ARM64 RVA 0x772d4 dereferences a table reachable from the PEB.
Upstream Wine: user32 DllMain -> winproc_init ->
win32u NtUserInitializeClientPfnArrays -> init_user -> gdi_init -> init_gdi_shared.
"""
from io import BytesIO
import hashlib
from pathlib import Path
from zipfile import ZipFile
import subprocess
import struct

import pefile

apk=Path("audit/app-release.apk")
expected={
    "native":"lib/wine/aarch64-unix/win32u.so",
    "pe_win32u":"lib/wine/aarch64-windows/win32u.dll",
    "pe_user32":"lib/wine/aarch64-windows/user32.dll",
    "pe_gdi32":"lib/wine/aarch64-windows/gdi32.dll",
}
def dig(x):return hashlib.sha256(x).hexdigest()
def run(*args):
    return subprocess.run(args,check=True,text=True,capture_output=True).stdout
with ZipFile(apk) as package:
    assert "assets/runtime/rm11-wine-stack.zip" in package.namelist()
    with ZipFile(BytesIO(package.read("assets/runtime/rm11-wine-stack.zip"))) as archive:
        print("RM11_WIN32U_GDI_INIT_BINARIES_V287")
        blobs={}
        for purpose,name in expected.items():
            blob=archive.read(name)
            assert len(blob)>4096
            blobs[purpose]=blob
            dst=Path("audit") / ("native-win32u.so" if purpose=="native" else name.split("/")[-1])
            dst.write_bytes(blob)
            print(purpose,name,"size",len(blob),"sha256",dig(blob))

        native=blobs["native"]
        assert native[:4]==b"\x7fELF" and native[4]==2
        assert native[18:20]==b"\xb7\x00"
        dynamic=run("readelf","-dW","audit/native-win32u.so")
        print("WIN32U_UNIX_ELF64_AARCH64_VERIFIED")
        for line in dynamic.splitlines():
            if "(NEEDED)" in line or "(RUNPATH)" in line or "(RPATH)" in line:
                print("UNIX_LINKER",line.strip())
        symbols=run("readelf","-Ws","audit/native-win32u.so")
        for needle in ("__wine_unix_lib_init","NtUserInitializeClientPfnArrays","gdi_init","init_gdi_shared"):
            found=[line.strip() for line in symbols.splitlines() if needle in line]
            print("UNIX_SYMBOL",needle,":",found[:4] if found else "STRIPPED_OR_NOT_EXPORTED")
        with open("audit/win32u-unix-elf-needed.txt","w") as out:
            out.write(dynamic)

        for key in ("pe_win32u","pe_user32","pe_gdi32"):
            exe=pefile.PE(data=blobs[key],fast_load=False)
            assert exe.FILE_HEADER.Machine == 0xaa64, (key,hex(exe.FILE_HEADER.Machine))
            assert exe.OPTIONAL_HEADER.Magic == 0x20b, key
            print("ARM64_PE_MODULE",key,hex(exe.OPTIONAL_HEADER.ImageBase))
            imports={}
            if hasattr(exe,"DIRECTORY_ENTRY_IMPORT"):
                for d in exe.DIRECTORY_ENTRY_IMPORT:
                    imports[d.dll.decode("ascii","replace").lower()]=[
                        sym.name.decode("ascii","replace") if sym.name else "#"+str(sym.ordinal)
                        for sym in d.imports]
            print("PE_IMPORT_MODULES",key,",".join(sorted(imports)))
            if key=="pe_user32":
                print("USER32_IMPORTS_WIN32U",imports.get("win32u.dll",[])[:80])
                print("USER32_IMPORTS_NTDLL",imports.get("ntdll.dll",[])[:25])
                assert "win32u.dll" in imports,"user32.dll has no win32u.dll imports - ABI may differ"
                assert "NtUserInitializeClientPfnArrays" in imports["win32u.dll"], (
                    "user32 does not import expected GUI callback initializer")
            if key=="pe_win32u":
                exports=[]
                if hasattr(exe,"DIRECTORY_ENTRY_EXPORT"):
                    exports=[
                        e.name.decode("ascii","replace") if e.name else "#"+str(e.ordinal)
                        for e in exe.DIRECTORY_ENTRY_EXPORT.symbols]
                print("PE_WIN32U_CALLBACK_INIT_EXPORT_PRESENT",
                      "NtUserInitializeClientPfnArrays" in exports)
                assert "NtUserInitializeClientPfnArrays" in exports
            print("PE_IMPORT_COUNT",key,sum(len(x) for x in imports.values()))
            exe.close()

        print("STRUCTURAL_CHAIN_USER32_TO_WIN32U_PRESENT")
        print("PROCESS_RUNTIME_CALLBACK_INVOCATION_UNVERIFIED")
        print("GDI_SHARED_HANDLE_TABLE_RUNTIME_INIT_UNVERIFIED")
        print("NO_GDI_CODE_PATCH_APPLIED")
