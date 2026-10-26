#!/usr/bin/env python3
"""Stage OFFICIAL x64 Windows DXVK/VKD3D DLLs as inert, verifiable APK assets.

No prefix modification, no driver installation, no implicit DLL overrides.
CI downloads exact upstream archives and checks official SHA-256 digests first.
"""
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import sys
import tarfile

EXPECTED = {
    "dxvk": ("40565b4a724aadc4433fa4e010b4b23916d9b1f1baeee64e17186db94f54e608",
             "3.1.1", ("d3d9.dll", "d3d10core.dll", "d3d11.dll", "dxgi.dll")),
    "vkd3d": ("3cf2315522af5e43605ef6d3c41dad91387040bf97199934f3f7ab76caaa2f0c",
              "3.0.1", ("d3d12.dll", "d3d12core.dll")),
}
OUT=pathlib.Path("app/src/main/assets/graphics/v456")

def fail(message):
    raise SystemExit("graphics-v456: " + message)

def pe_check(data, name):
    if len(data)<32768 or len(data)>40*1024*1024 or data[:2]!=b"MZ":
        fail("untrusted PE size/header: " + name)
    offset=struct.unpack_from("<I",data,0x3c)[0]
    if offset<64 or offset+26>len(data) or data[offset:offset+4]!=b"PE\\0\\0":
        fail("invalid PE signature: "+name)
    if struct.unpack_from("<H",data,offset+4)[0] != 0x8664:
        fail("DLL is not x86-64: "+name)
    if struct.unpack_from("<H",data,offset+24)[0] != 0x20b:
        fail("DLL is not PE32+: "+name)

def read_tar(path):
    if path.name.endswith(".zst"):
        run=subprocess.run(["zstd","-dc","--",str(path)],capture_output=True,check=True)
        if len(run.stdout)>300*1024*1024:
            fail("compressed package expanded beyond safe bound")
        return tarfile.open(fileobj=io.BytesIO(run.stdout),mode="r:")
    return tarfile.open(path,mode="r:gz")

def stage(component, archive):
    digest,version,requested=EXPECTED[component]
    actual=hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual!=digest: fail(component+" archive SHA256 mismatch: "+actual)
    with read_tar(archive) as tar:
        members=[m for m in tar.getmembers() if m.isfile()]
        paths={}
        for dll in requested:
            found=[m for m in members
                   if m.name.lower().replace("\\","/").endswith("/x64/"+dll)
                   or m.name.lower().replace("\\","/") == "x64/"+dll]
            if len(found)!=1: fail(component+": expected one x64/"+dll+"; found "+str(len(found)))
            member=found[0]
            if member.size>40*1024*1024: fail("oversize PE")
            data=tar.extractfile(member).read()
            pe_check(data,dll)
            dest=OUT/component/dll
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(data)
            paths[dll]={"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),
                        "asset":"graphics/v456/"+component+"/"+dll}
        # Keep upstream license text alongside DLLs where the release includes it.
        licenses=[m for m in members if pathlib.PurePosixPath(m.name).name.lower()
                  in ("license","license.txt","copying","copying.txt")]
        if licenses:
            license_member=min(licenses,key=lambda m:len(m.name))
            if license_member.size<160000:
                (OUT/component/"UPSTREAM-LICENSE.txt").write_bytes(
                    tar.extractfile(license_member).read())
    return {"version":version,"archive_sha256":digest,
            "source":("https://github.com/doitsujin/dxvk/releases/tag/v3.1.1"
                      if component=="dxvk" else
                      "https://github.com/HansKristian-Work/vkd3d-proton/releases/tag/v3.0.1"),
            "dlls":paths}

if __name__=="__main__":
    if len(sys.argv)!=3: fail("need DXVK tar.gz and VKD3D Proton tar.zst")
    d=stage("dxvk",pathlib.Path(sys.argv[1]))
    v=stage("vkd3d",pathlib.Path(sys.argv[2]))
    m={"schema":"rm11.graphics.staged.v456","active":False,
       "architecture":"win64-amd64-pe32plus","backend":"wine-arm64ec-fex",
       "warning":"STAGED ONLY: no registry override, prefix DLL replacement or GPU driver activation",
       "components":{"dxvk":d,"vkd3d":v}}
    (OUT/"manifest.json").write_text(json.dumps(m,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("Verified staged graphics assets:", json.dumps(
        {k:list(m["components"][k]["dlls"]) for k in ("dxvk","vkd3d")},sort_keys=True))
