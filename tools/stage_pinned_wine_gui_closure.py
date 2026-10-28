#!/usr/bin/env python3
"""Stage COMPLETE tested signed Wine/X11 native ELF dependency closure.

Physical v4.90.9 returns before Wine launch: missing libwine_winex11.so.
The historical SHA-pinned v4.0.89 APK contains the whole coherent Bionic
Wine/X11 closure. Preserve its exact bytes and do not mix old GPU stack.
This is static packaging verification only; does not assert game frames.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

PINNED_APK_SHA="1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8"
WINE_ALIAS_SONAMES={"ntdll.so","win32u.so"}
PLATFORM_SONAMES={
    "libc.so","libdl.so","libm.so","liblog.so","libz.so",
    "libandroid.so","libandroid_runtime.so","libEGL.so",
    "libGLESv2.so","libGLESv3.so","libstdc++.so",
    "libatomic.so","libvulkan.so","libmediandk.so",
    "libjnigraphics.so","libOpenSLES.so","libaaudio.so",
    "libsync.so","libnativewindow.so",
}
ROOTS={
    "libwine_winex11.so","libwine_win32u.so",
    "librm11_freetype_core.so",
    "libX11.so","libXext.so","libxcb.so","libandroid-sysvshm.so",
    "libwine_ws2_32.so",
    "librm11_win32u_fontclient.so","librm11_ft.so",
    "librm11_fc.so","libarm64ecfex.so","libwow64fex.so",
}
MAX_ELFS=55
MAX_TOTAL_BYTES=85*1024*1024
MAX_ELF_BYTES=22*1024*1024
SAFE_NAME=re.compile(r"lib[A-Za-z0-9._+\-]+\.so\Z")

def file_sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1<<20),b""):
            h.update(block)
    return h.hexdigest()

def verify_elf(data,name):
    if (len(data)<4096 or len(data)>MAX_ELF_BYTES or
        data[:6]!=bytes.fromhex("7f454c460201") or
        data[16:20]!=bytes.fromhex("0300b700")):
        raise ValueError("RM11_GUI_NATIVE_NOT_AARCH64_ET_DYN:"+name)

def needed(path):
    out=subprocess.run(["readelf","-dW",str(path)],
            check=True,capture_output=True,text=True).stdout
    return sorted(set(line.split("Shared library: [",1)[1].split("]",1)[0]
           for line in out.splitlines() if "Shared library: [" in line))

def stage(apk,output,report):
    apk,output,report=map(Path,(apk,output,report))
    if file_sha(apk)!=PINNED_APK_SHA:
        raise ValueError("RM11_GUI_SOURCE_SIGNED_PIN_MISMATCH")
    if output.is_symlink():
        raise ValueError("RM11_GUI_OUTDIR_SYMLINK")
    output.mkdir(parents=True,exist_ok=True)
    catalog={}
    with zipfile.ZipFile(apk) as archive:
        for i in archive.infolist():
            if i.filename.startswith("lib/arm64-v8a/") and i.filename.endswith(".so"):
                name=Path(i.filename).name
                if not SAFE_NAME.fullmatch(name) or i.file_size<=0 or i.file_size>MAX_ELF_BYTES:
                    raise ValueError("RM11_GUI_INVALID_NATIVE_FILE:"+name)
                if name in catalog:
                    raise ValueError("RM11_GUI_DUPLICATE_NATIVE_LIB:"+name)
                catalog[name]=i.filename
        missing=sorted(ROOTS-catalog.keys())
        if missing:raise ValueError("RM11_GUI_REQUIRED_NATIVE_MISSING:"+",".join(missing))
        with tempfile.TemporaryDirectory(prefix="rm11-pinned-gui-") as temp:
            scratch=Path(temp)
            staged={}
            queue=sorted(ROOTS)
            total=0
            while queue:
                name=queue.pop(0)
                if name in staged or name in PLATFORM_SONAMES or name in WINE_ALIAS_SONAMES:
                    continue
                if name not in catalog:
                    raise ValueError("RM11_GUI_NATIVE_DEPENDENCY_NOT_BUNDLED:"+name)
                data=archive.read(catalog[name])
                verify_elf(data,name)
                total+=len(data)
                if total>MAX_TOTAL_BYTES or len(staged)>=MAX_ELFS:
                    raise ValueError("RM11_GUI_NATIVE_CLOSURE_BUDGET_EXCEEDED")
                scratch_path=scratch/name
                scratch_path.write_bytes(data)
                imports=needed(scratch_path)
                staged[name]={"sha256":hashlib.sha256(data).hexdigest(),
                             "size_bytes":len(data),
                             "source_apk_entry":catalog[name],
                             "dt_needed":imports}
                for dep in imports:
                    if dep not in PLATFORM_SONAMES and dep not in WINE_ALIAS_SONAMES:
                        if not SAFE_NAME.fullmatch(dep):
                            raise ValueError("RM11_GUI_UNEXPECTED_DEPENDENCY_NAME:"+dep)
                        if dep not in queue and dep not in staged:
                            queue.append(dep)
            for name in sorted(staged):
                dest=output/name
                if dest.exists() or dest.is_symlink():
                    raise ValueError("RM11_GUI_TARGET_ALREADY_EXISTS:"+name)
            # Mutate only temporary CI app JNI staging after all hashes,
            # dependencies, filename/path budgets and preexisting collisions pass.
            for name in sorted(staged):
                dest=output/name
                data=(scratch/name).read_bytes()
                fd,tmp=tempfile.mkstemp(prefix=".rm11-gui-",dir=output)
                try:
                    with os.fdopen(fd,"wb") as f:
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp,dest)
                finally:
                    if os.path.exists(tmp):os.unlink(tmp)
                if file_sha(dest)!=staged[name]["sha256"]:
                    raise ValueError("RM11_GUI_NATIVE_STAGED_SHA_MISMATCH:"+name)
    result={
       "schema":"rm11.v49010.pinned-wine-x11-native-closure.v1",
       "source":"published_signed_v4_0_89_sha256_exact",
       "original_apk_sha256":PINNED_APK_SHA,
       "native_libraries":[{"library":name,**staged[name]} for name in sorted(staged)],
       "count":len(staged),"root_count":len(ROOTS),
       "wine_alias_needed":sorted(WINE_ALIAS_SONAMES),
       "prefix_modified":False,"turnip_provider_modified":False,
       "android_game_frame_proven":False,"engine_activation":False,
    }
    report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apk",type=Path,required=True)
    parser.add_argument("--outdir",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    r=stage(args.apk,args.outdir,args.report)
    print("RM11_V49010_SIGNED_GUI_NATIVE_CLOSURE_STAGED count="+str(r["count"]))
    print("RM11_V49010_GUI_NATIVE_BASENAMES="+",".join(x["library"] for x in r["native_libraries"]))

if __name__=="__main__":main()
