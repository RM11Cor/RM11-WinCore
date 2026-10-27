#!/usr/bin/env python3
"""Stage an ISOLATED Termux Bionic desktop Vulkan loader + Freedreno X11 ICD.

The existing Wine path is intentionally unchanged. No GPU backend becomes
active for games until on-device vkCreateInstance and X11 presentation pass.
Official Termux APT repositories provide SHA256 checks for every .deb. Copy
ONLY the ELF64 AArch64 DT_NEEDED closure. Every non-system SONAME gets a
private librm11_vk_* name and an ELF DT_NEEDED rewrite to avoid shadowing
Wine/X11 or Android's libvulkan.so. No untrusted user files are executed.
"""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from collections import deque
from pathlib import Path

from build_x11_bundle import (
    index_repositories, dep_choices, fetch, sha, elf_needed, is_arm64_elf,
    ANDROID_SYSTEM,
)

ROOT_PACKAGES = ("mesa-vulkan-icd-freedreno", "vulkan-loader-generic")
ROOT_LIBRARIES = ("libvulkan_freedreno.so", "libvulkan.so.1")
APK_LIBDIR = Path("app/src/main/jniLibs/arm64-v8a")
MANIFEST = Path("app/src/main/assets/runtime/rm11-v473-x11-vulkan-stage.json")
MAX_PACKAGES = 100
MAX_BYTES = 220 * 1024 * 1024
MAX_ELFS = 90

def run(*cmd):
    return subprocess.run(cmd,check=True,text=True,capture_output=True).stdout

def private_name(soname):
    if soname == "libvulkan_freedreno.so":
        return "librm11_vkdriver_v473.so"
    if soname in ("libvulkan.so.1","libvulkan.so"):
        return "librm11_vkloader_v473.so"
    if not re.fullmatch(r"lib[A-Za-z0-9_.+~-]+\.so(?:\.[0-9.]+)?",soname):
        raise RuntimeError("Unsafe ELF dependency name: "+soname)
    return "librm11_vk_"+re.sub(r"[^A-Za-z0-9]","_",soname)+".so"

def main():
    index, repositories = index_repositories()
    wanted=deque(ROOT_PACKAGES)
    chosen={}
    while wanted:
        name=wanted.popleft()
        if name in chosen:
            continue
        if name not in index:
            raise RuntimeError("Missing official Termux package "+name)
        pkg=index[name]
        chosen[name]=pkg
        if len(chosen)>MAX_PACKAGES:
            raise RuntimeError("Package count safety budget exceeded")
        for alternatives in dep_choices(pkg.get("Depends","")):
            found=next((a for a in alternatives if a in index),None)
            if found:
                wanted.append(found)

    catalog={}
    owner={}
    packages=[]
    total=0
    with tempfile.TemporaryDirectory(prefix="rm11-v473-vulkan-") as tmp:
        root=Path(tmp)
        for name,pkg in sorted(chosen.items()):
            url=pkg["_base"]+"/"+pkg["Filename"].lstrip("/")
            data=fetch(url,55*1024*1024)
            if sha(data).lower()!=pkg["SHA256"].lower():
                raise RuntimeError("Termux APT SHA256 mismatch: "+name)
            total+=len(data)
            if total>MAX_BYTES:
                raise RuntimeError("Overall upstream binary download budget exceeded")
            deb=root/(name+".deb")
            deb.write_bytes(data)
            extract=root/name
            extract.mkdir()
            run("dpkg-deb","-x",str(deb),str(extract))
            packages.append({"name":name,"version":pkg["Version"],
                             "sha256":sha(data),"source":url})
            deb.unlink()
            for candidate in extract.rglob("*"):
                if not candidate.is_file() or not re.search(r"\.so(?:\.[0-9.]+)?$",candidate.name):
                    continue
                if not is_arm64_elf(candidate):
                    continue
                old=catalog.get(candidate.name)
                if old and sha(old.read_bytes())!=sha(candidate.read_bytes()):
                    raise RuntimeError("Conflicting Termux ELF SONAME "+candidate.name+
                                       " from "+owner[candidate.name]+" and "+name)
                catalog[candidate.name]=candidate
                owner[candidate.name]=name

        # Default Termux packaging may contain symlink .so.1 into .so.
        if "libvulkan.so.1" not in catalog and "libvulkan.so" in catalog:
            catalog["libvulkan.so.1"]=catalog["libvulkan.so"]
        for required in ROOT_LIBRARIES:
            if required not in catalog:
                raise RuntimeError("Missing desktop Vulkan root ELF "+required)

        selected={}
        queue=deque(ROOT_LIBRARIES)
        while queue:
            soname=queue.popleft()
            if soname in ANDROID_SYSTEM or soname in selected:
                continue
            source=catalog.get(soname)
            if source is None:
                raise RuntimeError("Unresolved Vulkan ICD DT_NEEDED: "+soname)
            selected[soname]=source
            if len(selected)>MAX_ELFS:
                raise RuntimeError("Vulkan dependency closure count budget exceeded")
            for dependency in elf_needed(source):
                if dependency not in selected and dependency not in ANDROID_SYSTEM:
                    queue.append(dependency)
        aliases={soname:private_name(soname) for soname in selected}
        if len(set(aliases.values()))!=len(aliases):
            raise RuntimeError("Private ELF alias collision")
        APK_LIBDIR.mkdir(parents=True,exist_ok=True)
        MANIFEST.parent.mkdir(parents=True,exist_ok=True)
        staged=[]
        for soname,source in sorted(selected.items()):
            dest=APK_LIBDIR/aliases[soname]
            if dest.exists():
                raise RuntimeError("Refuse to overwrite previous native ELF "+str(dest))
            shutil.copyfile(source,dest)
            old_needed=elf_needed(dest)
            # patchelf only on our COPIES. Never modify original Wine/FEX or
            # upstream package bytes and never write to Android system dirs.
            run("patchelf","--set-soname",aliases[soname],str(dest))
            for dependency in old_needed:
                if dependency in aliases:
                    run("patchelf","--replace-needed",dependency,
                        aliases[dependency],str(dest))
            actual=elf_needed(dest)
            unexpected=[x for x in actual if x not in ANDROID_SYSTEM
                        and x not in aliases.values()]
            if unexpected:
                raise RuntimeError("Unclosed private DT_NEEDED: "+
                                   str({soname:unexpected}))
            if not is_arm64_elf(dest):
                raise RuntimeError("Incorrect architecture "+str(dest))
            staged.append({"upstream_soname":soname,"apk_library":aliases[soname],
                "sha256":sha(dest.read_bytes()),"bytes":dest.stat().st_size,
                "dt_needed":actual,"upstream_package":owner.get(soname,"vulkan-loader-generic")})
        out={
            "mode":"ISOLATED_STAGING_ONLY_NOT_SELECTED_FOR_WINE",
            "sources":repositories,"packages":packages,"native_libraries":staged,
            "loader":"librm11_vkloader_v473.so",
            "freedreno_icd":"librm11_vkdriver_v473.so",
            "x11_surface_creation":"UNVERIFIED",
            "hardware_frame_presentation":"UNVERIFIED",
            "overwrote_wine_fex_x11_or_android_driver":False,
            "upstream_licenses":"See official Termux and Mesa package license files",
        }
        MANIFEST.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
        print("RM11_V473_PINNED_TERMUX_X11_VULKAN_CLOSURE_STAGED",len(staged),
              "libraries, SHA256-checked packages",len(packages),flush=True)

if __name__=="__main__":
    main()
