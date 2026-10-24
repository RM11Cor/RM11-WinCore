#!/usr/bin/env python3
"""Bundle audited Bionic AArch64 FreeType and DT_NEEDED dependencies.

Use SHA256-authenticated official Termux APT packages; never take native code
from writable game folders or system-private Android libraries.
Ship the FreeType ELF under the signed APK's librm11_freetype.so filename.
Wine invokes SONAME_LIBFREETYPE through dlopen(), which the opt-in RM11 native
bridge maps only to this signed library. All dependency SONAMEs are unchanged.
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
    ANDROID_SYSTEM, dep_choices, elf_needed, fetch,
    index_repositories, is_arm64_elf, sha,
)

ROOT="freetype"
OUTPUT=Path("app/src/main/jniLibs/arm64-v8a")
REPORT=Path("app/src/main/assets/runtime/rm11-freetype-provenance.json")
MAX_BYTES=90*1024*1024
MAX_PKGS=32
MAX_LIBS=24

def main():
    packages, indexes=index_repositories()
    assert ROOT in packages, "Official Termux APT freetype package absent"
    chosen={}
    q=deque([ROOT])
    while q:
        name=q.popleft()
        if name in chosen: continue
        assert len(chosen)<MAX_PKGS, "Unbounded transitive APT package closure"
        p=packages.get(name)
        assert p, "Missing Termux dependency: "+name
        chosen[name]=p
        for alternatives in dep_choices(p.get("Depends","")):
            next_name=next((x for x in alternatives if x in packages),None)
            if next_name:q.append(next_name)
    manifest=[]
    sources={}
    total=0
    with tempfile.TemporaryDirectory(prefix="rm11-freetype-apt-") as root:
        root=Path(root)
        for name,p in sorted(chosen.items()):
            url=p["_base"]+"/"+p["Filename"].lstrip("/")
            blob=fetch(url,35*1024*1024)
            total+=len(blob)
            assert total<=MAX_BYTES,"Exceeded bounded official APT download"
            assert sha(blob).lower()==p["SHA256"].lower(),"APT SHA mismatch: "+name
            deb=root/(name+".deb")
            deb.write_bytes(blob)
            dest=root/name
            dest.mkdir()
            subprocess.run(["dpkg-deb","-x",str(deb),str(dest)],check=True)
            deb.unlink()
            manifest.append({"name":name,"version":p["Version"],
                             "url":url,"deb_sha256":sha(blob)})
            for file in dest.rglob("*"):
                if not file.is_file() or not is_arm64_elf(file):continue
                if ".so" not in file.name:continue
                previous=sources.get(file.name)
                if previous and sha(previous.read_bytes())!=sha(file.read_bytes()):
                    raise ValueError("APT SONAME mismatch "+file.name)
                sources[file.name]=file
        # Termux uses the Android/Bionic versionless SONAME by default;
        # accept the upstream .so.6 form too, but always install under the
        # unambiguous signed JNI basename librm11_freetype.so.
        actual=next((n for n in ("libfreetype.so","libfreetype.so.6")
                     if n in sources),None)
        assert actual, "Official Termux FreeType shared library absent"
        entries={}
        todo=deque([actual])
        while todo:
            soname=todo.popleft()
            if soname in ANDROID_SYSTEM or soname in entries:continue
            path=sources.get(soname)
            assert path, "Missing FreeType DT_NEEDED library "+soname
            assert len(entries)<MAX_LIBS, "Unexpectedly large native closure"
            entries[soname]=path
            for dep in elf_needed(path):
                if dep not in ANDROID_SYSTEM and dep not in entries:todo.append(dep)
        OUTPUT.mkdir(parents=True,exist_ok=True)
        # Android Gradle JNI accepts unversioned lib*.so only; Termux's
        # FreeType closure contains versioned SONAMEs (e.g. libbz2.so.1.0).
        # Rebase DT_SONAME and DT_NEEDED of the authenticated AArch64 ELF
        # copies to stable signed APK filenames using patchelf. Keep the
        # original provenance hashes and never edit archived Wine itself.
        assert shutil.which("patchelf"),"patchelf needed for SONAME normalization"
        pattern=re.compile(r"(lib[A-Za-z0-9_+.-]+\.so)(?:\.[0-9]+(?:\.[0-9]+)*)?$")
        translation={}
        for soname in entries:
            parsed=pattern.fullmatch(soname)
            assert parsed, "Unexpected ELF SONAME: "+soname
            target_name="librm11_freetype.so" if soname==actual else parsed.group(1)
            assert target_name not in translation.values(),"Normalized SONAME collision"
            translation[soname]=target_name
        original_sha={soname:sha(blob.read_bytes()) for soname,blob in entries.items()}
        all_entries=[]
        for soname,source in sorted(entries.items()):
            target_name=translation[soname]
            assert re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so",target_name),target_name
            target=OUTPUT/target_name
            contents=source.read_bytes()
            assert contents[:4]==b"\x7fELF",target_name
            # Stage in temporary, fully verify and only then copy into APK.
            transformed=root/("patched-"+target_name)
            transformed.write_bytes(contents)
            subprocess.run(["patchelf","--set-soname",target_name,str(transformed)],
                           check=True)
            for dependency in elf_needed(transformed):
                if dependency in translation and dependency!=translation[dependency]:
                    subprocess.run(["patchelf","--replace-needed",dependency,
                                    translation[dependency],str(transformed)],check=True)
            needed=elf_needed(transformed)
            for dependency in needed:
                if dependency not in ANDROID_SYSTEM:
                    assert dependency in translation.values(), (
                        "Unresolved rebased dependency "+dependency+" for "+target_name)
            assert is_arm64_elf(transformed),"Patched ELF no longer ARM64"
            patched=transformed.read_bytes()
            if target.exists():
                assert target.read_bytes()==patched, (
                    "Would overwrite previous native library "+target_name)
            else:target.write_bytes(patched)
            all_entries.append({"library":target_name,"original_soname":soname,
                                "original_sha256":original_sha[soname],
                                "sha256":sha(patched),"size":len(patched),
                                "dt_needed":needed})
        assert any(x["library"]=="librm11_freetype.so" for x in all_entries)
        assert len(all_entries)>=1
        REPORT.parent.mkdir(parents=True,exist_ok=True)
        REPORT.write_text(json.dumps({
            "purpose":"Read-only signed AArch64 Bionic FreeType for Wine GUI text",
            "source_indexes":indexes,"packages":manifest,
            "signed_native_libraries":all_entries,
            "freetype_original_soname":actual,
            "wine_dlopen_redirect_only_on_embedded_x11":True,
            "mutated_original_wine_or_prefix_files":False,
            "licensed_upstream":"See official Termux package and freetype LICENSE",
            "on_device_window_text_verified":False,
        },sort_keys=True,indent=2)+"\n")
        print("RM11_V298_AUDITED_FREETYPE_PACKAGE_VERIFIED",
              actual,len(all_entries),"libs, packages",len(manifest))
        for item in all_entries:print(item["library"],item["size"],item["sha256"])

if __name__=="__main__":main()
