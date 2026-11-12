#!/usr/bin/env python3
"""FH5 M80 - read-only nested archive metadata census on the user's own ZIP.

For ZIP_STORED nested ZIP members, central-directory metadata is read through
a bounded file view without copying/extracting the nested member, even if huge.
Deflated nested members are read only when small. Other methods are counted but
never circumvented. No game bytes, local file names, paths or hashes are uploaded.
This does not prove source authenticity, mesh decoding or game playability.
"""
from __future__ import annotations
import io, json, os, re, struct, sys, time, unittest, zipfile
from collections import Counter
from pathlib import Path

STAGE="M80"
OUT=Path("/sdcard/Download/FH5_M80")
PRIVATE=Path.home()/".fh5_m80"/"PRIVATE_NESTED_ARCHIVE_INDEX.json"
PREV79=Path("/sdcard/Download/FH5_M79/M79_INTEGRITY_REPORT.json")
PREV78=Path("/sdcard/Download/FH5_M78/M78_ARCHIVE_REPORT.json")
PATHS78=Path.home()/".fh5_m78"/"PRIVATE_ARCHIVE_SELECTION.json"
PATHS77=Path.home()/".fh5_m77"/"PRIVATE_SOURCE_CANDIDATES.json"
TARGET_EXTS=(".modelbin",".carbin",".materialbin",".shaderbin",
             ".swatchbin",".minizip",".bxml",".slt")
NESTED_EXTS=(".zip",".minizip")
MAX_OUTER_MEMBERS=50000
MAX_INNER_MEMBERS=80000
MAX_INSPECT=24
MAX_MEMORY_MEMBER=24*1024**2
MAX_MEMORY_BUDGET=64*1024**2
MAX_SECONDS=140
MAX_PUBLIC=100000

class SliceFile:
    """Seekable read-only view over one STORED entry, using pread on its real file."""
    def __init__(self, path, start, length):
        self.fd=os.open(path,os.O_RDONLY)
        self.start=start
        self.length=length
        self.pos=0
        self.closed=False
    def seek(self, offset, whence=0):
        if self.closed:raise ValueError("closed")
        if whence==0:p=offset
        elif whence==1:p=self.pos+offset
        elif whence==2:p=self.length+offset
        else:raise ValueError("whence")
        if p<0:raise ValueError("negative seek")
        self.pos=p
        return p
    def tell(self):return self.pos
    def read(self,n=-1):
        if self.closed:raise ValueError("closed")
        if self.pos>=self.length:return b""
        if n is None or n<0:n=self.length-self.pos
        n=min(n,self.length-self.pos)
        data=os.pread(self.fd,n,self.start+self.pos)
        self.pos+=len(data)
        return data
    def seekable(self):return True
    def readable(self):return True
    def close(self):
        if not self.closed:
            os.close(self.fd)
            self.closed=True
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def report_from(path,report_name,max_size=MAX_PUBLIC):
    try:
        if path.is_file() and path.suffix.lower()==".json" and path.stat().st_size<=max_size:
            return json.loads(path.read_text(encoding="utf8"))
        if path.is_file() and path.suffix.lower()==".zip":
            with zipfile.ZipFile(path) as z:
                info=z.getinfo(report_name)
                if info.file_size<=max_size:
                    return json.loads(z.read(info).decode("utf8"))
    except (OSError,ValueError,UnicodeError,RuntimeError,KeyError,zipfile.BadZipFile):
        pass
    return None

def load_prior():
    def load(folder,stem,stage):
        cands=[folder]
        cands += [Path("/sdcard/Download")/(f"FH5_{stage}_REPORTS.zip")]
        cands += [Path("/storage/emulated/0/Download")/(f"FH5_{stage}_REPORTS.zip")]
        for p in cands:
            v=report_from(p,f"FH5_{stage}/{stem}")
            if v:return v
        return None
    p79=load(PREV79,"M79_INTEGRITY_REPORT.json",79)
    p78=load(PREV78,"M78_ARCHIVE_REPORT.json",78)
    return p79,p78

def prior_ok(a,b):
    return (isinstance(a,dict) and isinstance(b,dict) and
        a.get("stage")=="M79" and
        a.get("status")=="M79_SAMPLED_CRC_PASS_NO_FULL_INTEGRITY_CLAIM" and
        a.get("crc_sample",{}).get("complete_crc_members",0)>0 and
        a.get("crc_sample",{}).get("crc_or_read_failures",1)==0 and
        a.get("crc_sample",{}).get("crc_or_length_failures",1)==0 and
        b.get("stage")=="M78" and
        b.get("status")=="M78_ZIP_METADATA_PREFLIGHT_COMPLETE" and
        isinstance(b.get("selected_archive_summary"),dict) and
        b.get("selected_archive_summary",{}).get("entries")==a.get("archive_file_entries") and
        b.get("selected_archive_summary",{}).get("uncompressed_bytes")==a.get("original_archive_payload_bytes"))

def get_candidate_paths():
    candidates=[]
    for source in (PATHS78,PATHS77):
        try:
            if not source.is_file() or source.stat().st_size>300000:continue
            v=json.loads(source.read_text(encoding="utf8"))
            if not isinstance(v,dict) or v.get("private_only") is not True:continue
            records=(v.get("archives",[]) if v.get("stage")=="M78"
                     else v.get("source_locations",[]) if v.get("stage")=="M77" else [])
            for item in records[:100]:
                if not isinstance(item,dict):continue
                s=item.get("path")
                if not isinstance(s,str):continue
                p=Path(s)
                if p.is_absolute() and p.is_file() and not p.is_symlink():
                    candidates.append(p)
        except (OSError,ValueError,UnicodeError,TypeError):continue
    unique={}
    for p in candidates:
        try:unique.setdefault(str(p.resolve()),p)
        except OSError:continue
    return list(unique.values())

def check_source(p, m78):
    expected=m78["selected_archive_summary"]
    try:
        with zipfile.ZipFile(p) as z:
            items=z.infolist()
            if len(items)>MAX_OUTER_MEMBERS:return False
            files=[i for i in items if not i.is_dir()]
            return (len(files)==expected.get("entries") and
                sum(i.file_size for i in files)==expected.get("uncompressed_bytes") and
                sum(i.filename.replace("\\","/").split("/")[-1].lower()=="forzahorizon5.exe"
                    for i in files)==expected.get("exe_count") and
                p.stat().st_size==expected.get("archive_bytes"))
    except (OSError,PermissionError,ValueError,RuntimeError,zipfile.BadZipFile):return False

def nested_name(info):
    name=info.filename.replace("\\","/").lower()
    return name.endswith(NESTED_EXTS)

def nested_score(i):
    low=i.filename.lower()
    return (30 if "cars" in low else 0)+(20 if "materials" in low else 0)+(
        10 if any(w in low for w in ("shader","track","media")) else 0)

def choose(items):
    candidates=[x for x in items if not x.is_dir() and nested_name(x)
            and not (x.flag_bits&1)]
    candidates.sort(key=lambda i:(-nested_score(i), i.file_size, i.filename.lower()))
    selected=[];used=set()
    def add(i):
        key=(i.filename,i.header_offset)
        if key not in used and len(selected)<MAX_INSPECT:
            selected.append(i);used.add(key)
    for i in candidates:
        if nested_score(i)>=20 and (i.compress_type==zipfile.ZIP_STORED or i.file_size<=MAX_MEMORY_MEMBER):
            add(i)
    stored=[i for i in candidates if i.compress_type==zipfile.ZIP_STORED]
    for seq in (stored,candidates):
        if seq:
            for n in range(12):
                add(seq[(n*(len(seq)-1))//11])
    for i in candidates:add(i)
    return candidates,selected

def stored_start(path,info):
    if info.compress_type!=zipfile.ZIP_STORED or info.file_size!=info.compress_size:
        raise ValueError("not stored")
    fd=os.open(path,os.O_RDONLY)
    try:
        hdr=os.pread(fd,30,info.header_offset)
    finally:os.close(fd)
    if len(hdr)!=30 or hdr[:4]!=b"PK\x03\x04":raise ValueError("local zip header")
    fn,extra=struct.unpack_from("<HH",hdr,26)
    start=info.header_offset+30+fn+extra
    if start<0 or start+info.file_size>path.stat().st_size:
        raise ValueError("entry boundary")
    return start

def classify_inner(z):
    members=z.infolist()
    if len(members)>MAX_INNER_MEMBERS:return {"status":"metadata_limit","entries":len(members)}
    counts=Counter();methods=Counter()
    for i in members:
        if i.is_dir():continue
        ext=Path(i.filename.replace("\\","/")).suffix.lower()
        if ext in TARGET_EXTS:counts[ext]+=1
        methods[str(i.compress_type)]+=1
    return dict(status="indexed",entries=sum(not i.is_dir() for i in members),
                asset_counts=dict(counts),compression_methods=dict(methods))

def inspect_inner(outer_path,outer,info,budget):
    if info.flag_bits&1:return dict(status="encrypted")
    if info.compress_type==zipfile.ZIP_STORED and info.file_size==info.compress_size:
        try:
            off=stored_start(outer_path,info)
            with SliceFile(outer_path,off,info.file_size) as view:
                with zipfile.ZipFile(view) as inner:
                    result=classify_inner(inner)
            result["access_mode"]="stored_seek_only"
            return result
        except (OSError,ValueError,RuntimeError,MemoryError,EOFError,
                zipfile.BadZipFile,struct.error):
            return dict(status="invalid_nested_zip",access_mode="stored_seek_only")
    if info.file_size>MAX_MEMORY_MEMBER or info.file_size>budget[0]:
        return dict(status="memory_limit")
    if info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED,
                                  zipfile.ZIP_BZIP2,zipfile.ZIP_LZMA):
        return dict(status="unsupported_outer_method")
    if info.compress_size==0 or info.file_size>info.compress_size*200:
        return dict(status="expansion_ratio_rejected")
    try:
        with outer.open(info) as f:
            buf=f.read(MAX_MEMORY_MEMBER+1)
        if len(buf)!=info.file_size or len(buf)>MAX_MEMORY_MEMBER:
            return dict(status="size_or_read_limit")
        budget[0]-=len(buf)
        with zipfile.ZipFile(io.BytesIO(buf)) as inner:
            result=classify_inner(inner)
        result["access_mode"]="bounded_memory"
        return result
    except (OSError,ValueError,RuntimeError,EOFError,MemoryError,zipfile.BadZipFile,
            NotImplementedError):
        return dict(status="unsupported_or_invalid_nested_zip")

def census(path, p79, p78, *, limit_seconds=MAX_SECONDS):
    until=time.monotonic()+limit_seconds
    private=[]
    with zipfile.ZipFile(path) as outer:
        files=[i for i in outer.infolist() if not i.is_dir()]
        all_nested,chosen=choose(files)
        totals=Counter();asset_counts=Counter();methods=Counter()
        results=[];budget=[MAX_MEMORY_BUDGET]
        for i in chosen:
            if time.monotonic()>until:
                totals["time_limit"]+=1
                break
            result=inspect_inner(path,outer,i,budget)
            totals[result["status"]]+=1
            if result["status"]=="indexed":
                asset_counts.update(result["asset_counts"])
                methods.update(result["compression_methods"])
            private.append(dict(member=i.filename,header_offset=i.header_offset,
                                status=result["status"]))
            results.append(result)
        state=("M80_NESTED_INDEXES_WITH_ASSET_NAMES" if sum(asset_counts.values()) else
               "M80_NESTED_INDEXES_NO_ASSET_MATCH" if totals["indexed"] else
               "M80_NO_NESTED_INDEX_VERIFIED")
        return dict(stage=STAGE,status=state,read_only=True,
            m79_sample_crc_gate=True,m78_source_metadata_gate=True,
            original_game_source_authenticated=False,independent_asset_provenance_verified=False,
            archive_entries=len(files),outer_nested_archive_names=len(all_nested),
            nested_archive_candidates_selected=len(chosen),nested_archive_candidates_attempted=len(results),
            nested_index_success=totals["indexed"],
            index_or_access_outcomes=dict(totals),matched_asset_name_counts=dict(asset_counts),
            inner_compression_method_counts=dict(methods),
            nested_data_crc_verified=False,internal_asset_bytes_extracted=False,
            original_carbin_decoded=False,original_modelbin_decoded=False,
            original_shader_decoded=False,game_port_complete=False,
            game_bytes_in_report=False,source_paths_in_report=False,
            interpretation="Named entries and compression IDs are metadata; they are not decoded meshes or verified original assets.",
            next_gate=("Validate a selected asset's provenance, internal compression method and byte header before implementing a format parser. "
                       "For unsupported ZIP methods, plan a documented safe decoder."),
            scan_time_limit_hit=bool(totals["time_limit"])),private

class Tests(unittest.TestCase):
    def fixture(self,method=zipfile.ZIP_STORED):
        import tempfile
        d=tempfile.TemporaryDirectory()
        p=Path(d.name)/"outer.zip"
        inner=io.BytesIO()
        with zipfile.ZipFile(inner,"w",zipfile.ZIP_DEFLATED) as z:
            z.writestr("Media/Cars/car/model.modelbin",b"test")
            z.writestr("Media/Cars/car/descriptor.carbin",b"test")
            z.writestr("Media/Textures/a.swatchbin",b"test")
        payload=inner.getvalue()
        with zipfile.ZipFile(p,"w",compression=method) as z:
            z.writestr("Media/Cars/carA.zip",payload)
        return d,p
    def test_slice(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as outer:
                i=outer.infolist()[0];off=stored_start(p,i)
                with SliceFile(p,off,i.file_size) as s:
                    self.assertEqual(s.read(4),b"PK\x03\x04")
                    self.assertEqual(s.seek(-22,2),i.file_size-22)
        finally:d.cleanup()
    def test_stored_nested_index(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                item=z.infolist()[0]
                result=inspect_inner(p,z,item,[MAX_MEMORY_BUDGET])
            self.assertEqual(result["status"],"indexed")
            self.assertEqual(result["asset_counts"][".modelbin"],1)
            self.assertEqual(result["access_mode"],"stored_seek_only")
        finally:d.cleanup()
    def test_deflated_small_index(self):
        d,p=self.fixture(zipfile.ZIP_DEFLATED)
        try:
            with zipfile.ZipFile(p) as z:
                result=inspect_inner(p,z,z.infolist()[0],[MAX_MEMORY_BUDGET])
            self.assertEqual(result["status"],"indexed")
            self.assertEqual(result["asset_counts"][".carbin"],1)
            self.assertEqual(result["access_mode"],"bounded_memory")
        finally:d.cleanup()
    def test_no_extraction(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                self.assertEqual(z.infolist()[0].file_size,len(z.read(z.infolist()[0])))
            self.assertEqual(list(Path(d.name).iterdir()),[p])
        finally:d.cleanup()
    def test_index_names_only(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                res=inspect_inner(p,z,z.infolist()[0],[MAX_MEMORY_BUDGET])
            self.assertEqual(res["asset_counts"][".swatchbin"],1)
            self.assertNotIn("Media/Cars",json.dumps(res))
        finally:d.cleanup()
    def test_prior_valid(self):
        a=dict(stage="M79",status="M79_SAMPLED_CRC_PASS_NO_FULL_INTEGRITY_CLAIM",
          archive_file_entries=10,original_archive_payload_bytes=99,
          crc_sample=dict(complete_crc_members=18,crc_or_read_failures=0,crc_or_length_failures=0))
        b=dict(stage="M78",status="M78_ZIP_METADATA_PREFLIGHT_COMPLETE",
          selected_archive_summary=dict(entries=10,uncompressed_bytes=99))
        self.assertTrue(prior_ok(a,b))
    def test_prior_bad(self):self.assertFalse(prior_ok({},{}))
    def test_bad_source(self):
        d,p=self.fixture()
        try:self.assertFalse(check_source(p,{"selected_archive_summary":{"entries":999}}))
        finally:d.cleanup()
    def test_candidate_selection(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:c,s=choose(z.infolist())
            self.assertEqual(len(c),1);self.assertEqual(len(s),1)
        finally:d.cleanup()
    def test_unknown_names(self):
        p=zipfile.ZipInfo("a/b/random.txt")
        self.assertFalse(nested_name(p))
    def test_unknown_inner_name_count(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,"w") as z:z.writestr("raw/x.dat",b"z")
        b.seek(0)
        with zipfile.ZipFile(b) as z:
            self.assertEqual(classify_inner(z)["asset_counts"],{})
    def test_memory_budget(self):
        d,p=self.fixture(zipfile.ZIP_DEFLATED)
        try:
            with zipfile.ZipFile(p) as z:
                r=inspect_inner(p,z,z.infolist()[0],[0])
            self.assertEqual(r["status"],"memory_limit")
        finally:d.cleanup()
    def test_not_authentic(self):
        self.assertFalse(prior_ok({"stage":"M79"},{"stage":"M78"}))
    def test_no_path_in_public(self):
        d,p=self.fixture()
        try:
            a=dict(stage="M79");b=dict(stage="M78")
            report,private=census(p,a,b)
            self.assertNotIn(str(p),json.dumps(report))
            self.assertNotIn("carA.zip",json.dumps(report))
            self.assertIn("carA.zip",json.dumps(private))
            self.assertFalse(report["original_modelbin_decoded"])
        finally:d.cleanup()
    def test_invalid_slice(self):
        d,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                info=z.infolist()[0]
                info.compress_type=zipfile.ZIP_DEFLATED
                with self.assertRaises(ValueError):stored_start(p,info)
        finally:d.cleanup()

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    stream=io.StringIO()
    tests=unittest.TextTestRunner(stream=stream,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (OUT/"M80_LOCAL_TESTS.txt").write_text(stream.getvalue(),encoding="utf8")
    report={"stage":STAGE,"status":"M80_SELFTEST_FAILURE"}
    private=[]
    if tests.wasSuccessful():
        p79,p78=load_prior()
        if not prior_ok(p79,p78):
            report={"stage":STAGE,"status":"M80_PRIOR_REPORT_MISSING_OR_INVALID"}
        else:
            paths=get_candidate_paths()
            path=next((p for p in paths if check_source(p,p78)),None)
            if path is None:
                report={"stage":STAGE,"status":"M80_ORIGINAL_ARCHIVE_PATH_NOT_FOUND",
                    "next_gate":"Keep the original ZIP in its Termux-visible location; rerun M78 if local selection was deleted."}
            else:
                try:report,private=census(path,p79,p78)
                except (OSError,ValueError,RuntimeError,MemoryError,zipfile.BadZipFile):
                    report={"stage":STAGE,"status":"M80_SOURCE_READ_ERROR"}
    if private:
        PRIVATE.parent.mkdir(parents=True,exist_ok=True)
        PRIVATE.write_text(json.dumps({"stage":STAGE,"private_only":True,
            "selected_nested_entries":private},indent=2)+"\n",encoding="utf8")
        try:PRIVATE.chmod(0o600)
        except OSError:pass
    (OUT/"M80_NESTED_INDEX_REPORT.json").write_text(
        json.dumps(report,indent=2)+"\n",encoding="utf8")
    (OUT/"M80_STATUS.txt").write_text(report["status"]+"\n",encoding="utf8")
    dest=OUT.parent/"FH5_M80_REPORTS.zip"
    with zipfile.ZipFile(dest,"w",zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.glob("M80_*")):
            if p.is_file() and p.suffix in (".json",".txt"):z.write(p,"FH5_M80/"+p.name)
    print("[M80]",report["status"])
    print("[M80] Public report:",dest)
    print("[M80] Original game and nested archives were NOT extracted to disk.")
    return 0 if report["status"].startswith("M80_NESTED_INDEXES_") else 17

if __name__=="__main__":
    raise SystemExit(main())
