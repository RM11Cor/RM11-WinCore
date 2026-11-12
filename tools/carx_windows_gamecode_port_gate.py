#!/usr/bin/env python3
"""CarX Street PC -> native Android port feasibility from user's OWN local files.

Strictly read-only, offline and bounded. This tool does not execute, modify,
decrypt, dump or distribute the game. It measures real Windows PE imports and
Addressables catalog platform paths, NOT a claim of a playable native port.

Run: python3 tools/carx_windows_gamecode_port_gate.py \
       "/sdcard/Download/CarX Street" --out carx_gamecode_port_gate.json
"""
from __future__ import annotations
import argparse
import json
import re
import struct
from pathlib import Path
from typing import Any

SCHEMA="rm11carx.winpc-gamecode-and-addressables-to-android-gate.v1"
MAX_PE_SIZE=1_073_741_824
MAX_CATALOG_BYTES=32_000_000
MAX_SECTIONS=128
MAX_IMPORTS=256
MAX_IMPORT_NAME=256
MAX_PE_HEADERS=1_048_576

class FormatError(Exception):
    pass

def require(ok: bool,reason: str)->None:
    if not ok: raise FormatError(reason)

def u16(raw:bytes,at:int)->int:
    require(0<=at<=len(raw)-2,"truncated PE uint16")
    return struct.unpack_from("<H",raw,at)[0]

def u32(raw:bytes,at:int)->int:
    require(0<=at<=len(raw)-4,"truncated PE uint32")
    return struct.unpack_from("<I",raw,at)[0]

def simple_name(raw:bytes)->str:
    stop=raw.find(b"\0")
    require(0<stop<=MAX_IMPORT_NAME,"unbounded or missing PE import string")
    name=raw[:stop]
    require(all(0x20<=b<0x7f for b in name),"nonprinting PE library name")
    return name.decode("ascii")

def inspect_pe(file:Path)->dict[str,Any]:
    require(file.is_file() and not file.is_symlink(),"only local regular non-symlink PE file")
    size=file.stat().st_size
    require(256<=size<=MAX_PE_SIZE,"invalid or oversized Windows game binary")
    with file.open("rb") as f:
        head=f.read(min(size,MAX_PE_HEADERS))
        require(head[:2]==b"MZ","not original DOS/PE MZ signature")
        peoff=u32(head,0x3c)
        require(0x40<=peoff<=min(size-256,MAX_PE_HEADERS-320),
                "PE signature offset outside bounded header")
        require(head[peoff:peoff+4]==b"PE\0\0","invalid original PE signature")
        machine=u16(head,peoff+4)
        section_count=u16(head,peoff+6)
        optional_bytes=u16(head,peoff+20)
        characteristics=u16(head,peoff+22)
        require(0<section_count<=MAX_SECTIONS,"invalid PE section count")
        opt=peoff+24
        require(optional_bytes>=112 and opt+optional_bytes<=len(head),
                "truncated original PE optional header")
        magic=u16(head,opt)
        require(magic in (0x10b,0x20b),"only valid PE32/PE32+ images")
        is64=magic==0x20b
        datadir_off=112 if is64 else 96
        require(optional_bytes>=datadir_off+16,"missing PE import directory")
        section_off=opt+optional_bytes
        require(section_off+section_count*40<=len(head),"truncated PE section table")
        sections=[]
        for i in range(section_count):
            at=section_off+i*40
            name=head[at:at+8].split(b"\0",1)[0].decode("ascii","replace")
            vsize=u32(head,at+8)
            rva=u32(head,at+12)
            rawlen=u32(head,at+16)
            rawoff=u32(head,at+20)
            require(rawlen==0 or (rawoff<=size and rawlen<=size-rawoff),
                    "PE section raw bytes outside file")
            sections.append((rva,vsize,rawoff,rawlen,name))
        def rva_to_offset(rva:int,minimum:int=1)->int:
            require(rva!=0,"PE missing RVA")
            for address,vsize,rawoff,rawlen,_ in sections:
                if address<=rva<address+max(vsize,rawlen):
                    delta=rva-address
                    require(delta+minimum<=rawlen,"PE RVA points to memory-only bytes")
                    at=rawoff+delta
                    require(at+minimum<=size,"PE RVA points outside file")
                    return at
            raise FormatError("PE RVA not mapped to original section")
        imports=[]
        directory_rva=u32(head,opt+datadir_off+8)
        directory_size=u32(head,opt+datadir_off+12)
        if directory_rva:
            require(20<=directory_size<=MAX_IMPORTS*20+20,
                    "invalid or unbounded PE import descriptor bytes")
            base=rva_to_offset(directory_rva,20)
            f.seek(base)
            descriptors=f.read(directory_size)
            require(len(descriptors)==directory_size,"truncated import descriptor data")
            terminated=False
            for off in range(0,min(directory_size//20,MAX_IMPORTS)*20,20):
                a,b,c,d,e=struct.unpack_from("<5I",descriptors,off)
                if (a,b,c,d,e)==(0,0,0,0,0):
                    terminated=True
                    break
                require(d!=0,"PE import descriptor lacks name RVA")
                nameoff=rva_to_offset(d,1)
                f.seek(nameoff)
                dll=simple_name(f.read(MAX_IMPORT_NAME+1))
                imports.append(dll)
            require(terminated,"PE imports not terminated within bounded directory")
        names=sorted(set(x.lower() for x in imports))
        system_win32=("kernel32.dll","kernelbase.dll","ntdll.dll","user32.dll",
                      "gdi32.dll","advapi32.dll","ws2_32.dll","shell32.dll",
                      "ole32.dll","d3d11.dll","dxgi.dll","d3d12.dll","winmm.dll")
        return {
            "pe_valid":True,
            "file_size":size,
            "pe_machine_hex":hex(machine),
            "architecture":{
                0x8664:"x86_64",0xaa64:"ARM64",0x14c:"x86_32"
            }.get(machine,f"other_{machine:x}"),
            "file_format":"PE32+" if is64 else "PE32",
            "dll_characteristics":characteristics,
            "section_count":section_count,
            "section_names":[x[4] for x in sections][:MAX_SECTIONS],
            "import_dll_names":names,
            "windows_system_imports":[s for s in names if s in system_win32],
            "steam_related_imports":[s for s in names if "steam" in s],
            "anti_cheat_related_imports":[s for s in names
                    if "easyanticheat" in s or s.startswith("eac")],
            "eos_related_imports":[s for s in names if "eos" in s],
            "import_names_are_not_complete_runtime_dependencies":True,
            "android_elf_bionic_binary":False,
            "android_game_code_execution_proven":False,
            "native_android_game_code_recompilation_inputs_proven":False,
        }

def inspect_catalog(file:Path)->dict[str,Any]:
    require(file.is_file() and not file.is_symlink(),"only existing local catalog")
    size=file.stat().st_size
    require(2<=size<=MAX_CATALOG_BYTES,"too large or invalid addressables catalog")
    with file.open("r",encoding="utf-8") as f:
        catalog=json.load(f)
    require(isinstance(catalog,dict),"Unity Addressables catalog must be object")
    ids=catalog.get("m_InternalIds")
    require(isinstance(ids,list) and len(ids)<=100_000,
            "missing or unbounded Addressables m_InternalIds list")
    require(all(isinstance(x,str) and len(x)<=8192 for x in ids),
            "unbounded/non-string internal Addressables IDs")
    values=[x.lower() for x in ids]
    windows=sum("standalonewindows64" in x for x in values)
    linux=sum("standalonelinux64" in x for x in values)
    mac=sum("standaloneosx" in x for x in values)
    android=sum(("android" in x or "/aa/android/" in x) for x in values)
    bundle_like=sum(x.endswith((".bundle",".unity3d",".assetbundle")) for x in values)
    shader_like=sum("shader" in x for x in values)
    return {
        "catalog_present":True,
        "catalog_bytes":size,
        "internal_id_count":len(ids),
        "windows64_reference_count":windows,
        "linux64_reference_count":linux,
        "macos_reference_count":mac,
        "android_named_reference_count":android,
        "bundle_extension_reference_count":bundle_like,
        "shader_named_reference_count":shader_like,
        "contains_references_to_windows_only_platform":windows>0,
        "android_named_references_do_not_prove_android_bundles":True,
        "android_runtime_asset_load_proven":False,
        "full_internal_asset_dependency_graph_parsed":False,
        "windows_bundles_to_android_converted":False,
    }

def find_casefold(root:Path,name:str,children=()):
    for candidate in (root,*[root/p for p in children]):
        if not candidate.is_dir():
            continue
        for p in candidate.iterdir():
            if p.name.casefold()==name.casefold() and p.is_file():
                return p
    return None

def inspect_game(root:Path)->dict[str,Any]:
    require(root.is_dir() and not root.is_symlink(),
            "original local PC CarX root directory required")
    report={
        "schema":SCHEMA,
        "scope":"read-only owner-provided PC PE import tables and Unity catalog",
        "executed_or_modified_game_binary":False,
        "accessed_anticheat_private_state":False,
        "game_code_inputs":{},
        "assets":{},
        "android_arm64_game_logic_available":False,
        "android_assetbundle_targets_proven":False,
        "native_pc_to_android_port_proven":False,
        "original_game_first_frame_proven":False,
    }
    for label,name in (("game_il2cpp","GameAssembly.dll"),
                       ("unity_player","UnityPlayer.dll")):
        file=find_casefold(root,name)
        if not file:
            report["game_code_inputs"][label]={"present":False}
        else:
            try:
                report["game_code_inputs"][label]={
                    "present":True,**inspect_pe(file)}
            except (OSError,FormatError,struct.error) as error:
                report["game_code_inputs"][label]={
                    "present":True,"pe_valid":False,
                    "error":str(error)[:180]}
    catalog = None
    variants = [
        root/"CarX Street_Data"/"StreamingAssets"/"aa"/"catalog.json",
        root/"CarXStreet_Data"/"StreamingAssets"/"aa"/"catalog.json",
    ]
    catalog=next((p for p in variants if p.is_file()),None)
    if catalog:
        try:
            report["assets"]=inspect_catalog(catalog)
        except (OSError,FormatError,ValueError,json.JSONDecodeError) as error:
            report["assets"]={"catalog_present":True,"catalog_valid":False,
                              "error":str(error)[:180]}
    else:
        report["assets"]={"catalog_present":False}
    report["native_game_code_gate"]="BLOCKED_NO_AUTHORIZED_ANDROID_ARM64_CARX_GAME_LOGIC"
    report["asset_gate"]="BLOCKED_NO_PROVEN_ANDROID_TARGET_UNITY_BUNDLES"
    report["reason"]=(
        "Original Windows GameAssembly DLL and Windows-target Addressables cannot "
        "automatically produce an Android/Bionic native game. Need lawful "
        "Android ARM64 IL2CPP gameplay build/source and platform-correct assets. "
        "A preconfigured compatibility APK is NOT a strict native game port."
    )
    return report

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("game_directory",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    result=inspect_game(args.game_directory)
    serialized=json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(serialized,encoding="utf-8")
    else:
        print(serialized)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
