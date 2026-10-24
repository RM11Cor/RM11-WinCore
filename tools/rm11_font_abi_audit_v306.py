#!/usr/bin/env python3
"""Read-only CI audit of pinned Wine 11 Win32u FreeType ABI vs v3.0.5 signed APK.

This is intentionally NOT an Android APK build and does NOT turn on any
experimental FreeType Wine hook that correlated with wineserver crashes.
Records exact original SHA and opaque dynamic symbol/SONAME fingerprints.
"""
from __future__ import annotations
import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

FT_FUNCTIONS = [
    "FT_Done_Face", "FT_Get_Char_Index", "FT_Get_First_Char",
    "FT_Get_Next_Char", "FT_Get_Sfnt_Name", "FT_Get_Sfnt_Name_Count",
    "FT_Get_Sfnt_Table", "FT_Get_TrueType_Engine_Type",
    "FT_Get_WinFNT_Header", "FT_Init_FreeType", "FT_Library_SetLcdFilter",
    "FT_Library_Version", "FT_Load_Glyph", "FT_Load_Sfnt_Table",
    "FT_Matrix_Multiply", "FT_MulDiv", "FT_MulFix",
    "FT_New_Face", "FT_New_Memory_Face", "FT_Outline_Embolden",
    "FT_Outline_Get_Bitmap", "FT_Outline_Get_CBox",
    "FT_Outline_Transform", "FT_Outline_Translate",
    "FT_Property_Set", "FT_Render_Glyph", "FT_Set_Charmap",
    "FT_Set_Pixel_Sizes", "FT_Vector_Length", "FT_Vector_Transform",
    "FT_Vector_Unit",
]

def sha(data: bytes)->str:
    return hashlib.sha256(data).hexdigest()

def run(args:list[str])->str:
    x=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     text=True,check=True)
    return x.stdout

def elf_report(path: Path)->dict:
    info=run(["readelf","-hW",str(path)])
    assert "AArch64" in info and "ELF64" in info, f"wrong ARM64 ABI: {path}"
    dyn=run(["readelf","-dW",str(path)])
    sym=run(["readelf","-WsW",str(path)])
    needed=re.findall(r"\(NEEDED\).*?\[([^]]+)\]",dyn)
    symbols=set(re.findall(r"\b(FT_[A-Za-z0-9_]+)(?:@@?\S*)?(?:\s|$)",sym))
    return {"bytes":path.stat().st_size,"sha256":sha(path.read_bytes()),
            "dt_needed":needed,"ft_export_count":len(symbols),
            "matched_expected_ft_symbols":sorted(symbols.intersection(FT_FUNCTIONS)),
            "missing_expected_ft_symbols":sorted(set(FT_FUNCTIONS)-symbols)}

def main(apk_path:str,out_dir:str):
    root=Path(out_dir);root.mkdir(parents=True,exist_ok=True)
    report={"version":"v3.0.5-signed-original","read_only":True,
            "wine_font_hook_enabled":False,"wine_client_crash_risk": "NOT_EXERCISED"}
    with zipfile.ZipFile(apk_path) as apk:
        names=set(apk.namelist())
        runtime="assets/runtime/rm11-wine-stack.zip"
        assert runtime in names
        with zipfile.ZipFile(io.BytesIO(apk.read(runtime))) as wine:
            source="lib/wine/aarch64-unix/win32u.so"
            assert source in wine.namelist()
            win32u=wine.read(source)
            (root/"win32u-source.so").write_bytes(win32u)
            report["original_wine_win32u"]=elf_report(root/"win32u-source.so")
            report["wine_freetype_soname_literals"]=sorted(set(
                token.decode("ascii","replace")
                for token in re.findall(
                    rb"lib(?:free(?:type)?|fontconfig)[A-Za-z0-9.+_-]*\.so(?:\.[0-9.]+)?",
                    win32u)))
            report["Wine_Win32u_expected_symbol_strings"]={
                fn: (fn.encode("ascii")+b"\x00") in win32u
                for fn in FT_FUNCTIONS
            }
        signed_win32u="lib/arm64-v8a/libwine_win32u.so"
        if signed_win32u in names:
            report["signed_win32u_identical_source"]=apk.read(signed_win32u)==win32u
        expected="lib/arm64-v8a/librm11_freetype_core.so"
        assert expected in names,"Pinned signed NDK FreeType not present"
        (root/"signed-freetype-core.so").write_bytes(apk.read(expected))
        report["signed_freetype_core"]=elf_report(root/"signed-freetype-core.so")
        lib_names=sorted(name.removeprefix("lib/arm64-v8a/") for name in names
                         if name.startswith("lib/arm64-v8a/") and name.endswith(".so"))
        report["signed_fontconfig_library_available"]=any("fontconfig" in x for x in lib_names)
        report["signed_freetype_core_available"]=True
    runtime_symbols={n for n,yes in report["Wine_Win32u_expected_symbol_strings"].items() if yes}
    exported=set(report["signed_freetype_core"]["matched_expected_ft_symbols"])
    report["required_runtime_font_symbols"]=sorted(runtime_symbols)
    report["missing_required_runtime_symbols"]=sorted(runtime_symbols-exported)
    # This cannot prove text or Wine server safety; outputs binary evidence
    # so next runtime repair avoids blindly swapping font implementations.
    (root/"font-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("RM11_V306_ORIGINAL_WIN32U_SHA256",report["original_wine_win32u"]["sha256"])
    print("RM11_V306_SIGNED_FREETYPE_SHA256",report["signed_freetype_core"]["sha256"])
    print("RM11_V306_REQUIRED_FONT_ABI_SYMBOL_COUNT",len(runtime_symbols))
    print("RM11_V306_MISSING_FT_ABI_SYMBOLS",report["missing_required_runtime_symbols"])
    print("RM11_V306_FONTCONFIG_STRINGS",report["wine_freetype_soname_literals"])
    print("RM11_V306_SIGNED_FONTCONFIG_PRESENT",report["signed_fontconfig_library_available"])
    print("RM11_V306_SIGNED_WIN32U_MATCHES_WINE_SOURCE",report.get("signed_win32u_identical_source"))
    print("RM11_V306_READONLY_FONT_AUDIT_SUCCEEDED")

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("Usage: audit.py signed.apk output_dir")
    main(sys.argv[1],sys.argv[2])
