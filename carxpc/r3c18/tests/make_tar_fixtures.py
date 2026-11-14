#!/usr/bin/env python3
"""R3C18 safe tar.gz fixtures: no Wine content, no device execution."""
from pathlib import Path
import tarfile,io,hashlib,json,sys
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
REQUIRED=[
 "usr/share/wine/wine.inf",
 "usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll",
 "usr/lib/wine/wine64",
 "tmp/kernix-real-win32-smoke.exe",
]
def obj(path,typ="file",value=b"ok",mode=0o644):
    return (path,typ,value,mode)
def make(name,entries):
    dest=out/(name+".tar.gz")
    with tarfile.open(dest,"w:gz",format=tarfile.PAX_FORMAT) as t:
        for path,kind,data,mode in entries:
            h=tarfile.TarInfo(path);h.mtime=0;h.uid=0;h.gid=0
            h.mode=mode
            if kind=="file":
                h.size=len(data);t.addfile(h,io.BytesIO(data))
            elif kind=="dir":
                h.type=tarfile.DIRTYPE;h.size=0;t.addfile(h)
            elif kind=="symlink":
                h.type=tarfile.SYMTYPE;h.linkname=data;t.addfile(h)
            elif kind=="hardlink":
                h.type=tarfile.LNKTYPE;h.linkname=data;t.addfile(h)
            elif kind=="special":
                h.type=tarfile.CHRTYPE;h.devmajor=1;h.devminor=3;t.addfile(h)
            else:raise AssertionError(kind)
    return hashlib.sha256(dest.read_bytes()).hexdigest()
basic=[obj(x,value=(b"#!/bin/sh\n" if x.endswith("/wine64") else b"ok"),mode=(0o755 if x.endswith("/wine64") else 0o644)) for x in REQUIRED]
success=[
  obj("./","dir"),
  *basic,
  obj("usr/bin/wine","symlink","../lib/wine/wine64"),
  obj("usr/bin/wine64","hardlink","usr/lib/wine/wine64"),
  obj("dev/null","special")
]
cases={
 "good":success,
 "traversal":[*basic,obj("../escape","file",b"ESCAPE")],
 "absolute":[*basic,obj("/outside","file",b"ESCAPE")],
 "drive_path":[*basic,obj("C:\\evil","file",b"ESCAPE")],
 "dot_component":[*basic,obj("usr/../escape","file",b"ESCAPE")],
 "duplicate":[*basic,obj(REQUIRED[0],"file",b"OVERWRITE")],
 "missing_required":basic[:-1],
 "symlink_escape":[*basic,obj("usr/bin/escape","symlink","../../../outside")],
 "hardlink_escape":[*basic,obj("usr/bin/escape","hardlink","../../outside")],
 "hardlink_symlink":[*basic,obj("usr/bin/foo","symlink","../lib/wine/wine64"),obj("usr/bin/alias","hardlink","usr/bin/foo")],
 "symlink_absolute_inside":[*basic,obj("usr/bin/wine","symlink","/usr/lib/wine/wine64")],
 "special_outside_dev":[*basic,obj("usr/share/exploit","special")],
}
metadata={name:make(name,entries) for name,entries in cases.items()}
# Additional corrupt-header fixture with a re-computed compressed digest:
import gzip
raw=gzip.decompress((out/"good.tar.gz").read_bytes())
b=bytearray(raw);b[0]^=1
(out/"checksum_bad.tar.gz").write_bytes(gzip.compress(bytes(b)))
metadata["checksum_bad"]=hashlib.sha256((out/"checksum_bad.tar.gz").read_bytes()).hexdigest()
(out/"fixtures.json").write_text(json.dumps(metadata,sort_keys=True,indent=2)+"\n")
print("CARX_R3C18_SAFE_TAR_TEST_FIXTURES_GENERATED",len(metadata))
