#!/usr/bin/env python3
"""FH5 M37: inspect a downloaded game archive WITHOUT extracting the game.
ZIP: Python standard library. RAR/7z: optional 7z / 7zz CLI.
A static archive NEVER reveals the GPU runtime b2 uniform or descriptor count.
"""
import argparse, json, re, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
from collections import Counter

MAX_ENTRIES=500000
MAX_7Z_LIST=64*1024*1024
REGEX_FIRST_RAR=re.compile(r"(?i)\.part0*1\.rar$")
TRACKED={".materialbin",".modelbin",".shaderbin",".swatchbin",".carbin",".pso",".vso"}

def find_archives(directory):
    found=[]
    for p in directory.iterdir():
        if not p.is_file(): continue
        n=p.name.lower()
        if REGEX_FIRST_RAR.search(n) or n.endswith((".zip",".7z",".rar",".7z.001",".zip.001")):
            if re.search(r"(?i)\.part\d+\.rar$",n) and not REGEX_FIRST_RAR.search(n):
                continue
            found.append(p)
    return sorted(found,key=lambda p:(-int(any(s in p.name.lower() for s in ("forza","horizon","fh5"))),-p.stat().st_size,p.name))

def part_gaps(path):
    n=path.name
    m=re.match(r"(?i)^(.*?)\.part(\d+)\.rar$",n)
    if m:
        base,width=m.group(1),len(m.group(2))
        pat=re.compile(re.escape(base)+r"\.part(\d{"+str(width)+r"})\.rar$",re.I)
    else:
        m=re.match(r"(?i)^(.*\.(?:7z|zip))\.(\d{3})$",n)
        if not m: return {"kind":"single or unknown","volume_completeness_proven":False}
        base=m.group(1);pat=re.compile(re.escape(base)+r"\.(\d{3})$",re.I)
    nums={int(x.group(1)) for p in path.parent.iterdir() if p.is_file() if (x:=pat.match(p.name))}
    return {"kind":"multipart","volumes_detected":len(nums),
            "missing_between_1_and_last":[i for i in range(1,max(nums,default=0)+1) if i not in nums][:100],
            "last_volume_is_final_proven":False}

class Index:
    def __init__(self):
        self.entries=0;self.bytes=0;self.encrypted=0;self.unsafe=0
        self.types=Counter();self.matches=[];self.shader_zip=0;self.exe=False
    def add(self,name,size=0,encrypted=False,is_dir=False):
        if is_dir:return
        self.entries+=1
        if self.entries>MAX_ENTRIES: raise ValueError("Too many entries; stopped at 500000")
        self.bytes+=max(0,int(size));self.encrypted+=bool(encrypted)
        q=name.replace("\\","/");l=q.lower()
        if q.startswith("/") or re.search(r"(^|/)\.\.(/|$)",q):self.unsafe+=1
        s=Path(l).suffix
        if s in TRACKED:self.types[s]+=1
        kind=None
        if l.endswith("/shaders.zip") or l=="shaders.zip":
            self.shader_zip+=1;kind="nested_Shader_library"
        elif re.search(r"(^/|^)(forzahorizon5|forzahorizon5steam)\.exe$",l):
            self.exe=True;kind="potential_game_exe"
        elif "pg_trafficvehicles/" in l and l.endswith((".shaderbin",".pcdxil.pso",".pcdxil.vso")):
            kind="original_traffic_shader"
        if kind and len(self.matches)<100:
            self.matches.append({"kind":kind,"path":q,"uncompressed_bytes":int(size)})
    def result(self):
        return {"entries":self.entries,"declared_uncompressed_bytes":self.bytes,
                "encrypted_entries":self.encrypted,"path_traversal_entries_not_extracted":self.unsafe,
                "relevant_suffix_counts":dict(self.types),"nested_shaders_zip_count":self.shader_zip,
                "game_exe_name_found":self.exe,"matched_members_first100":self.matches}

def zip_listing(p,idx):
    with zipfile.ZipFile(p,"r",allowZip64=True) as z:
        for i in z.infolist():
            idx.add(i.filename,i.file_size,bool(i.flag_bits&1),i.is_dir())
    return "ZIP central directory; no extraction; CRC contents NOT tested"

def seven_zip_listing(p,idx):
    binary=next((x for x in ("7zz","7z","7za") if shutil.which(x)),None)
    if not binary:
        raise RuntimeError("RAR/7z needs 7-Zip. Ubuntu: apt update && apt install -y 7zip (or p7zip-full)")
    proc=subprocess.Popen([binary,"l","-slt","-bd","--",str(p)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    data={};started=False;total=0
    def close_entry():
        if "Path" not in data:return
        try:size=int(data.get("Size","0"))
        except ValueError:size=0
        idx.add(data["Path"],size,data.get("Encrypted")=="+" ,
                data.get("Folder")=="+" or data.get("Attributes","").startswith("D"))
    try:
        for line in proc.stdout:
            total+=len(line)
            if total>MAX_7Z_LIST:raise ValueError("7-Zip listing too big (64 MiB safety limit)")
            s=line.decode("utf-8","replace").rstrip("\r\n")
            if s.startswith("----------"):started=True;continue
            if not started:continue
            if s.startswith("Path = "):
                close_entry();data={"Path":s[7:]}
            elif not s:
                close_entry();data={}
            elif " = " in s and data:
                a,b=s.split(" = ",1);data[a]=b
        close_entry()
    except Exception:
        proc.kill();proc.wait();raise
    if proc.wait()!=0 or not started:
        raise RuntimeError("7-Zip could not list archive: incomplete volume, password, or damaged archive")
    return binary+" technical listing; no extraction"

def inspect(path,download):
    idx=Index()
    report={"stage":"M37","archive_filename":path.name,"archive_bytes":path.stat().st_size,
            "part_status":part_gaps(path),"free_bytes_in_download_storage":shutil.disk_usage(download).free,
            "extracted":False,"contents_crc_verified":False,
            "runtime_b2_row71_values_available":False,
            "runtime_space6_srv_descriptor_capacity_available":False,
            "m36_real_runtime_capacity_gate_evaluable":False}
    method=zip_listing(path,idx) if zipfile.is_zipfile(path) else seven_zip_listing(path,idx)
    report.update(idx.result());report["inspection_method"]=method
    report["status"]="ARCHIVE_METADATA_ONLY"
    report["note"]=("Game archive names and sizes are not runtime GPU data. Even a "
                    "complete extracted game is insufficient to prove M36 b2/capacity.")
    return report

def test():
    with tempfile.TemporaryDirectory() as temp:
        folder=Path(temp);p=folder/"FH5.zip"
        with zipfile.ZipFile(p,"w") as z:
            z.writestr("Forza Horizon 5/media/_library/Shaders.zip",b"sample")
            z.writestr("ForzaHorizon5.exe",b"sample")
            z.writestr("Forza Horizon 5/media/_library/Shaders/pg_trafficvehicles/traffic_vehicle_glass.shaderbin",b"sample")
            z.writestr("../unsafe.txt",b"sample")
        a=inspect(p,folder)
        assert a["entries"]==4 and a["nested_shaders_zip_count"]==1
        assert a["game_exe_name_found"] and a["path_traversal_entries_not_extracted"]==1
        assert a["runtime_b2_row71_values_available"] is False
        assert a["m36_real_runtime_capacity_gate_evaluable"] is False
        assert a["extracted"] is False
        assert len(find_archives(folder))==1
        assert not (folder/"Forza Horizon 5").exists()
    print("M37 synthetic ZIP test: PASS (no original game assets, no extraction)")

def main():
    ap=argparse.ArgumentParser(description="FH5 M37: inspect local game archive without unpacking")
    ap.add_argument("--scan",type=Path,default=Path("/sdcard/Download"))
    ap.add_argument("--archive",type=Path,help="Exact downloaded archive pathname")
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    if args.self_test:test();return
    d=args.scan
    if not d.is_dir():ap.error("Download directory not found; use --scan /storage/emulated/0/Download")
    p=args.archive
    if not p:
        opts=find_archives(d)
        if not opts:ap.error("No ZIP/RAR/7z archive in Download; use --archive FILE")
        if len(opts)==1:p=opts[0]
        else:
            print("Choose your Forza Horizon 5 archive:")
            for i,f in enumerate(opts[:40],1):print(f"{i:>2}: {f.name} ({f.stat().st_size/2**30:.2f} GiB)")
            if not sys.stdin.isatty():ap.error("Multiple archives; use --archive '/sdcard/Download/NAME'")
            try:n=int(input("Archive number: "));p=opts[n-1] if 1<=n<=min(len(opts),40) else None
            except (ValueError,EOFError):p=None
    if not p or not p.is_file():ap.error("Cannot find archive path")
    try:r=inspect(p,d)
    except (ValueError,OSError,RuntimeError,zipfile.BadZipFile) as e:
        print("M37 ERROR:",str(e),file=sys.stderr);raise SystemExit(2)
    out=d/"FH5_M37_ARCHIVE_REPORT.json"
    out.write_text(json.dumps(r,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("M37: METADATA INSPECTION OK — no game files extracted")
    print("Archive:",r["archive_filename"],"Files:",r["entries"])
    print("Shaders.zip:",r["nested_shaders_zip_count"],"Game EXE:",r["game_exe_name_found"])
    print("REPORT:",out)
    print("Real GPU runtime b2/capacity still unknown. Upload the JSON report to continue.")

if __name__=="__main__":main()
