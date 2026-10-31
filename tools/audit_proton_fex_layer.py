#!/usr/bin/env python3
"""Security-first inventory for a trusted upstream Proton ARM64EC WCP.
No extraction and no game or Wine-prefix modifications are performed.
The report determines the real archive layout before we integrate or install it.
"""
import argparse
import json
import pathlib
import subprocess
import tarfile
import zipfile

def inspect(path):
    with path.open("rb") as stream: header=stream.read(16)
    kind = "unknown"
    names=[]
    if header.startswith(b"PK\x03\x04"):
        kind="zip"
        with zipfile.ZipFile(path) as archive:
            names=[(i.filename, i.file_size) for i in archive.infolist()]
    else:
        # GNU tar supports upstream xz/gzip/zstd via installed decompressor.
        for command in (["tar","--zstd","-tf",str(path)],
                        ["tar","-J","-tf",str(path)],
                        ["tar","-z","-tf",str(path)],
                        ["tar","-tf",str(path)]):
            r=subprocess.run(command,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,timeout=90)
            if r.returncode==0:
                kind="tar:"+command[1]
                names=[(n,0) for n in r.stdout.decode("utf-8","replace").splitlines()]
                break
    if not names: raise RuntimeError("PROTON_WCP_UNRECOGNIZED_ARCHIVE")
    if len(names)>100000: raise RuntimeError("PROTON_WCP_ENTRY_BUDGET")
    for name,_ in names:
        p=pathlib.PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise RuntimeError("PROTON_WCP_UNSAFE_PATH")
    selected=[{"path":n,"size":size} for n,size in names if
              any(t in n.lower() for t in ("ntdll","winebus","fex",
                     "wine64","wineserver","wine.inf","proton","manifest",
                     "wineboot","winegcc","libwine"))][:130]
    return {"schema":"kernix.proton-fex-audit.v1",
        "source":"The412Banner/proton-wine build-bionic-layers-20261030-v16",
        "archive_sha256":"ed77f62ec52926b0faca7f2e9decad58865bdc8ec975c63b15903a8da35f8ae6",
        "archive_format":kind,
        "file_count":len(names),
        "sample_files":selected,
        "root_folders":sorted(set(n.split("/")[0] for n,_ in names))[:40],
        "contains_arm64ec":any("arm64ec" in n.lower() or "aarch64" in n.lower() for n,_ in names),
        "mentions_fex":any("fex" in n.lower() for n,_ in names),
        "contains_ntdll":any("ntdll" in n.lower() for n,_ in names)}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--archive",required=True)
    p.add_argument("--report",required=True)
    a=p.parse_args()
    result=inspect(pathlib.Path(a.archive))
    pathlib.Path(a.report).write_text(json.dumps(result,indent=2)+"\n")
    if not result["contains_ntdll"]:
        raise RuntimeError("PROTON_WCP_MISSING_NTDLL")
if __name__=="__main__": main()
