#!/usr/bin/env python3
"""Ship an authenticated, private Termux/Bionic Fontconfig ELF closure.

Only the explicitly user-requested v4.0.9 Winefile test can dlopen this
library. Do not load from writable game files or expose a global SONAME alias.
All ELF dependencies are translated to signed APK JNI lib filenames.
"""
import hashlib
import json
import re
import subprocess
import tempfile
from collections import deque
from pathlib import Path
from build_x11_bundle import (
    ANDROID_SYSTEM, dep_choices, elf_needed, fetch,
    index_repositories, is_arm64_elf, sha,
)

OUTPUT=Path("app/src/main/jniLibs/arm64-v8a")
MANIFEST=Path("app/src/main/assets/runtime/rm11-v409-fontconfig-provenance.json")
MAX_PACKAGES=40
MAX_DOWNLOAD=80*1024*1024
MAX_LIBS=16

def main():
    packages,indexes=index_repositories()
    selected={}
    todo=deque(["fontconfig"])
    while todo:
        name=todo.popleft()
        if name in selected:continue
        p=packages.get(name)
        if not p:raise RuntimeError("Missing signed Termux package "+name)
        selected[name]=p
        if len(selected)>MAX_PACKAGES:raise RuntimeError("Fontconfig APT closure too big")
        for alt in dep_choices(p.get("Depends","")):
            next_name=next((x for x in alt if x in packages),None)
            if next_name:todo.append(next_name)
    retrieved=0
    sources={}
    pkg_metadata=[]
    with tempfile.TemporaryDirectory(prefix="rm11-v409-fc-") as temp:
        root=Path(temp)
        for name,p in sorted(selected.items()):
            data=fetch(p["_base"]+"/"+p["Filename"].lstrip("/"),35*1024*1024)
            retrieved+=len(data)
            if retrieved>MAX_DOWNLOAD:raise RuntimeError("Bounded Fontconfig download exceeded")
            if sha(data).lower()!=p["SHA256"].lower():raise RuntimeError("APT SHA mismatch "+name)
            deb=root/(name+".deb")
            deb.write_bytes(data)
            dest=root/name
            dest.mkdir()
            subprocess.run(["dpkg-deb","-x",str(deb),str(dest)],check=True)
            deb.unlink()
            pkg_metadata.append({"package":name,"version":p["Version"],"sha256":sha(data)})
            for file in dest.rglob("*"):
                if not file.is_file() or ".so" not in file.name or not is_arm64_elf(file):continue
                if file.name in sources:
                    if sha(file.read_bytes())!=sha(sources[file.name].read_bytes()):
                        raise RuntimeError("duplicate SONAME disagreement "+file.name)
                sources[file.name]=file
        rootlib=next((x for x in ("libfontconfig.so","libfontconfig.so.1") if x in sources),None)
        if not rootlib:raise RuntimeError("Missing Fontconfig AArch64 library")
        needed=deque([rootlib])
        chosen={}
        while needed:
            name=needed.popleft()
            if name in chosen or name in ANDROID_SYSTEM:continue
            item=sources.get(name)
            if not item:raise RuntimeError("Missing signed ELF dependency "+name)
            chosen[name]=item
            if len(chosen)>MAX_LIBS:raise RuntimeError("Unexpectedly large ELF closure")
            for dep in elf_needed(item):
                if dep not in chosen and dep not in ANDROID_SYSTEM:needed.append(dep)
        targetnames={}
        for name in chosen:
            if name==rootlib:
                native="librm11_fc.so"
            else:
                m=re.fullmatch(r"lib([A-Za-z0-9_+.-]+)\.so(?:\.[0-9.]+)?",name)
                if not m:raise RuntimeError("Unexpected native SONAME "+name)
                component=m.group(1).replace(".","_").replace("-","_")
                native="librm11_fc_"+component+".so"
            if native in targetnames.values():raise RuntimeError("Native alias collision")
            targetnames[name]=native
        OUTPUT.mkdir(parents=True,exist_ok=True)
        records=[]
        for name,path in sorted(chosen.items()):
            staged=root/("rebased-"+targetnames[name])
            staged.write_bytes(path.read_bytes())
            subprocess.run(["patchelf","--set-soname",targetnames[name],str(staged)],check=True)
            for dep in elf_needed(staged):
                if dep in targetnames and dep!=targetnames[dep]:
                    subprocess.run(["patchelf","--replace-needed",dep,targetnames[dep],str(staged)],check=True)
            dependencies=elf_needed(staged)
            for dep in dependencies:
                if dep not in ANDROID_SYSTEM and dep not in targetnames.values():
                    raise RuntimeError("Unresolved rebased native dependency "+dep)
            if not is_arm64_elf(staged):raise RuntimeError("Non-ARM64 patched Fontconfig ELF")
            dest=OUTPUT/targetnames[name]
            blob=staged.read_bytes()
            if dest.exists() and dest.read_bytes()!=blob:
                raise RuntimeError("Refuse replacing unrelated native ELF "+dest.name)
            dest.write_bytes(blob)
            records.append({"original_soname":name,"signed_library":dest.name,
                            "sha256":hashlib.sha256(blob).hexdigest(),
                            "size":len(blob),"needed":dependencies})
        MANIFEST.parent.mkdir(parents=True,exist_ok=True)
        MANIFEST.write_text(json.dumps({
            "schema":"rm11.v409.signed-fontconfig-closure.v1",
            "source_indexes":indexes,"packages":pkg_metadata,
            "native_libraries":records,
            "fontconfig_entry":"librm11_fc.so",
            "scope":"user-clicked isolated font test only",
            "font_dirs":"app-private fixed Wine fonts only",
            "wine_default_unchanged":True,
            "on_device_text_verified":False
        },sort_keys=True,indent=2)+"\n")
        print("RM11_V409_PRIVATE_FONTCONFIG_CLOSURE_SIGNABLE",len(records))
        for item in records:print(item["signed_library"],item["size"],item["sha256"])

if __name__=="__main__":main()
