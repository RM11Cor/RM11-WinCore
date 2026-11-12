#!/usr/bin/env python3
"""FH5 M79: bounded ZIP CRC sample and asset-header census, no extraction.

This is a source diagnostic, NOT a game port or source authentication.
Only aggregate measurements go into the uploadable report. Local archive paths
and sampled byte prefixes are never included in public artifacts.
"""
from __future__ import annotations
import io
import json
import os
import re
import shutil
import time
import unittest
import zipfile
import zlib
from collections import Counter
from pathlib import Path

STAGE = "M79"
OUT = Path("/sdcard/Download/FH5_M79")
PUBLIC_78 = Path("/sdcard/Download/FH5_M78/M78_ARCHIVE_REPORT.json")
PRIVATE_78 = Path.home()/".fh5_m78"/"PRIVATE_ARCHIVE_SELECTION.json"
PRIVATE_77 = Path.home()/".fh5_m77"/"PRIVATE_SOURCE_CANDIDATES.json"
DATA_EXT = (".modelbin", ".carbin", ".shaderbin", ".materialbin",
            ".bin", ".dat", ".pak", ".arc", ".bundle", ".data", ".big", ".fsb")
PRIORITY_EXT = (".modelbin", ".carbin", ".shaderbin", ".materialbin",
                ".bin", ".dat", ".pak", ".arc", ".bundle", ".data", ".big", ".fsb")
MAX_MEMBERS = 50000
MAX_CRC_TOTAL = 384*1024*1024
MAX_CRC_ENTRY = 192*1024*1024
MAX_CRC_ITEMS = 18
MAX_HEADER_ITEMS = 32
MAX_HEADER_BYTES = 256
MAX_SECONDS = 150
CHUNK = 1024*1024
MAX_METADATA_REPORT = 100000

def report_m78_ok(v):
    if not isinstance(v, dict): return False
    selected = v.get("selected_archive_summary")
    return (v.get("stage") == "M78" and
            v.get("status") == "M78_ZIP_METADATA_PREFLIGHT_COMPLETE" and
            v.get("source_state") == "PE64_GAME_NAMED_ZIP_WITH_DATA" and
            isinstance(selected, dict) and
            selected.get("exe_count", 0) >= 1 and
            selected.get("pe64_count", 0) >= 1 and
            selected.get("central_directory_read") is True and
            v.get("game_files_extracted") is False)

def load_m78():
    try:
        if PUBLIC_78.is_file() and PUBLIC_78.stat().st_size <= MAX_METADATA_REPORT:
            obj=json.loads(PUBLIC_78.read_text(encoding="utf8"))
            if report_m78_ok(obj): return obj
    except (OSError, ValueError, UnicodeError): pass
    # A previous uploadable report may still be in Downloads without its folder.
    for p in (Path("/sdcard/Download/FH5_M78_REPORTS.zip"),
              Path("/storage/emulated/0/Download/FH5_M78_REPORTS.zip")):
        try:
            if not p.is_file(): continue
            with zipfile.ZipFile(p) as z:
                item=z.getinfo("FH5_M78/M78_ARCHIVE_REPORT.json")
                if item.file_size>MAX_METADATA_REPORT: continue
                obj=json.loads(z.read(item).decode("utf8"))
                if report_m78_ok(obj): return obj
        except (OSError, ValueError, UnicodeError, zipfile.BadZipFile,
                RuntimeError, KeyError): pass
    return None

def is_exe(name):
    return name.replace("\\", "/").split("/")[-1].lower() == "forzahorizon5.exe"

def zip_magic(path):
    try:
        with path.open("rb") as f:
            return f.read(4) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    except (OSError, PermissionError): return False

def candidate_paths():
    found=[]
    for file in (PRIVATE_78, PRIVATE_77):
        try:
            if not file.is_file() or file.stat().st_size>250000: continue
            doc=json.loads(file.read_text(encoding="utf8"))
            if doc.get("private_only") is not True:continue
            source=(doc.get("archives", []) if doc.get("stage")=="M78"
                    else doc.get("source_locations", []) if doc.get("stage")=="M77" else [])
            if not isinstance(source, list):continue
            for entry in source[:100]:
                if not isinstance(entry, dict):continue
                val=entry.get("path")
                if not isinstance(val,str):continue
                p=Path(val)
                if p.is_absolute() and p.is_file() and not p.is_symlink() and zip_magic(p):
                    found.append(p)
        except (OSError, ValueError, UnicodeError, TypeError): pass
    unique={}
    for p in found:
        try: unique.setdefault(str(p.resolve()),p)
        except OSError:continue
    return list(unique.values())

def metadata_match(path, expected):
    """Metadata identity gate, NOT cryptographic file identity."""
    target=expected.get("selected_archive_summary",{})
    try:
        with zipfile.ZipFile(path) as z:
            members=z.infolist()
            if len(members)>MAX_MEMBERS: return False
            files=[i for i in members if not i.is_dir()]
            return (sum(i.file_size for i in files)==target.get("uncompressed_bytes")
                    and len(files)==target.get("entries")
                    and sum(is_exe(i.filename) for i in files)==target.get("exe_count")
                    and path.stat().st_size==target.get("archive_bytes"))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):return False

def known_header(data):
    # Named prefix family only. Does not prove that payload is compressed.
    if data.startswith((b"PK\x03\x04",b"PK\x05\x06")):return "zip"
    if data.startswith(b"\x28\xb5\x2f\xfd"):return "zstd"
    if data.startswith(b"\x04\x22\x4d\x18"):return "lz4_frame"
    if data.startswith(b"\x1f\x8b"):return "gzip"
    if data.startswith(b"\xfd7zXZ\x00"):return "xz"
    if len(data)>=2 and (data[0]&15)==8 and (data[0]>>4)<=7 and ((data[0]<<8)|data[1])%31==0:
        return "possible_zlib"
    if data.startswith(b"MZ"):return "mz"
    return "unclassified"

def safe_to_read(info):
    return (not info.is_dir() and not info.flag_bits & 1 and info.file_size>=0
            and (info.file_size==0 or (info.compress_size>0 and
                    info.file_size<=info.compress_size*1000)))

def file_ext(info):
    return Path(info.filename.replace("\\","/")).suffix.lower()

def pick_crc(files):
    eligible=[i for i in files if safe_to_read(i) and
              0<i.file_size<=MAX_CRC_ENTRY]
    exes=sorted((i for i in eligible if is_exe(i.filename)),key=lambda i:i.file_size)
    chosen=[];used=set();total=0
    def add(i):
        nonlocal total
        if len(chosen)>=MAX_CRC_ITEMS or i.filename in used or i.file_size+total>MAX_CRC_TOTAL:
            return False
        chosen.append(i);used.add(i.filename);total+=i.file_size
        return True
    for i in exes: add(i)
    # Preserve a variety of formats and sizes without randomness or disclosing names.
    for ext in PRIORITY_EXT:
        matches=sorted((i for i in eligible if file_ext(i)==ext),key=lambda i:i.file_size)
        for i in (matches[len(matches)//2],matches[0],matches[-1]) if matches else ():
            add(i)
    # Deterministic index spread ensures more than just the first few entries.
    remaining=sorted(eligible,key=lambda i:(i.file_size, i.filename))
    if remaining:
        for num in range(64):
            i=remaining[min(len(remaining)-1,num*(len(remaining)-1)//63)]
            add(i)
    return chosen

def sample_headers(z, files, until):
    counts=Counter();selected=[]
    for ext in PRIORITY_EXT:
        matches=[i for i in files if file_ext(i)==ext and safe_to_read(i) and i.file_size]
        if not matches:continue
        matches.sort(key=lambda i:i.file_size)
        for i in (matches[0],matches[len(matches)//2],matches[-1]):
            if i.filename not in {a.filename for a in selected}:
                selected.append(i)
    for i in selected[:MAX_HEADER_ITEMS]:
        if time.monotonic()>until:
            counts["budget_stop"]+=1
            break
        try:
            with z.open(i) as src:
                data=src.read(MAX_HEADER_BYTES)
            counts["read"]+=1
            counts["family_"+known_header(data)]+=1
        except (OSError,RuntimeError,ValueError,EOFError,zipfile.BadZipFile,zlib.error):
            counts["read_errors"]+=1
    return dict(headers_sampled=counts["read"],errors=counts["read_errors"],
                time_budget_stopped=bool(counts["budget_stop"]),
                prefix_family_counts={name[7:]:value for name,value in counts.items()
                                      if name.startswith("family_")})

def sample_crc(z, files, until):
    selected=pick_crc(files);out=Counter();done=0
    for info in selected:
        if time.monotonic()>until:
            out["budget_stop"]+=1;break
        crc=0;length=0;complete=False
        try:
            with z.open(info) as stream:
                while True:
                    if time.monotonic()>until:
                        out["budget_stop"]+=1;break
                    part=stream.read(CHUNK)
                    if not part:
                        complete=True
                        break
                    crc=zlib.crc32(part,crc);length+=len(part)
            if complete and length==info.file_size and crc==info.CRC:
                out["verified"]+=1;done+=length
                out["exe_verified"]+=is_exe(info.filename)
                out["asset_verified"]+=file_ext(info) in DATA_EXTS
            elif complete:
                out["crc_or_length_failures"]+=1
        except (OSError,RuntimeError,ValueError,EOFError,zipfile.BadZipFile,zlib.error):
            out["crc_or_read_failures"]+=1
    return dict(selected_members=len(selected),complete_crc_members=out["verified"],
                complete_crc_bytes=done,exe_crc_members=out["exe_verified"],
                data_crc_members=out["asset_verified"],
                crc_or_length_failures=out["crc_or_length_failures"],
                crc_or_read_failures=out["crc_or_read_failures"],
                time_budget_stopped=bool(out["budget_stop"]),
                total_archive_payload_crc_verified=False)

def inspect_zip(path,expected):
    if not metadata_match(path,expected):
        return {"stage":STAGE,"status":"M79_SOURCE_CHANGED_OR_MISMATCHED",
                "m78_validated_source_reused":False}
    until=time.monotonic()+MAX_SECONDS
    try:
        with zipfile.ZipFile(path) as z:
            files=[i for i in z.infolist() if not i.is_dir()]
            extension_counts=Counter(file_ext(i) for i in files)
            grouped={ext:extension_counts[ext] for ext in PRIORITY_EXT if extension_counts[ext]}
            encrypted=sum(bool(i.flag_bits&1) for i in files)
            unsupported=sum(i.compress_type not in (zipfile.ZIP_STORED,
                              zipfile.ZIP_DEFLATED,zipfile.ZIP_BZIP2,
                              zipfile.ZIP_LZMA) for i in files)
            header=sample_headers(z,files,until)
            crc=sample_crc(z,files,until)
            clean=crc["complete_crc_members"]>0 and (
                crc["crc_or_length_failures"]+crc["crc_or_read_failures"]==0)
            state=("M79_SAMPLED_CRC_PASS_NO_FULL_INTEGRITY_CLAIM" if clean
                   else "M79_SAMPLED_CRC_INCOMPLETE_OR_FAILED")
            return dict(stage=STAGE,status=state,read_only=True,
                m78_validated_source_reused=True,source_identity_cryptographically_verified=False,
                archive_file_entries=len(files),original_archive_payload_bytes=sum(i.file_size for i in files),
                candidate_asset_suffix_counts=grouped,encrypted_entries=encrypted,
                unsupported_zip_compression_entries=unsupported,
                header_census=header,crc_sample=crc,
                full_payload_crc_verified=False,all_archive_members_verified=False,
                original_asset_format_decoded=False,source_authenticated=False,
                game_port_complete=False,game_files_extracted=False,upload_contains_game_bytes=False,
                next_gate=("Continue to versioned original-asset header research directly from ZIP, "
                           "without extracting the 109 GB game; sampled CRC does not validate full archive."))
    except (OSError,ValueError,zipfile.BadZipFile,RuntimeError,MemoryError):
        return {"stage":STAGE,"status":"M79_UNREADABLE_SOURCE"}

class Tests(unittest.TestCase):
    def fixture(self):
        import tempfile
        temp=tempfile.TemporaryDirectory()
        p=Path(temp.name)/"sample.zip"
        with zipfile.ZipFile(p,"w",zipfile.ZIP_STORED) as z:
            z.writestr("ForzaHorizon5.exe",b"MZ"+bytes(1000))
            z.writestr("media/car.modelbin",b"ABCD"*100)
        return temp,p
    def test_gate_valid(self):
        self.assertTrue(report_m78_ok({"stage":"M78","status":"M78_ZIP_METADATA_PREFLIGHT_COMPLETE",
           "source_state":"PE64_GAME_NAMED_ZIP_WITH_DATA","game_files_extracted":False,
           "selected_archive_summary":{"exe_count":1,"pe64_count":1,"central_directory_read":True}}))
    def test_gate_bad(self):self.assertFalse(report_m78_ok({"stage":"M78"}))
    def test_exe_case(self):self.assertTrue(is_exe("GAME/FORZAHORIZON5.EXE"))
    def test_other_exe(self):self.assertFalse(is_exe("other.exe"))
    def test_zlib(self):self.assertEqual(known_header(b"\x78\x9c"),"possible_zlib")
    def test_zstd(self):self.assertEqual(known_header(b"\x28\xb5\x2f\xfd"),"zstd")
    def test_plain(self):self.assertEqual(known_header(b"ABCD"),"unclassified")
    def test_safe(self):
        with zipfile.ZipFile(io.BytesIO(),"w") as _:pass
        i=zipfile.ZipInfo("x.modelbin");i.file_size=100;i.compress_size=30
        self.assertTrue(safe_to_read(i))
    def test_no_zipbomb(self):
        i=zipfile.ZipInfo("x.modelbin");i.file_size=200000;i.compress_size=2
        self.assertFalse(safe_to_read(i))
    def test_metadata_match(self):
        t,p=self.fixture()
        try:
            expected={"selected_archive_summary":{"entries":2,
              "uncompressed_bytes":1402,"exe_count":1,"archive_bytes":p.stat().st_size}}
            self.assertTrue(metadata_match(p,expected))
        finally:t.cleanup()
    def test_metadata_mismatch(self):
        t,p=self.fixture()
        try:self.assertFalse(metadata_match(p,{"selected_archive_summary":{"entries":3}}))
        finally:t.cleanup()
    def test_crc_pass(self):
        t,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                r=sample_crc(z,[i for i in z.infolist() if not i.is_dir()],time.monotonic()+5)
            self.assertEqual(r["complete_crc_members"],2)
            self.assertEqual(r["crc_or_read_failures"],0)
        finally:t.cleanup()
    def test_corrupt_crc_detected(self):
        t,p=self.fixture()
        try:
            content=bytearray(p.read_bytes());needle=b"ABCD"*100
            pos=content.find(needle);self.assertGreater(pos,0)
            content[pos]+=1;p.write_bytes(content)
            with zipfile.ZipFile(p) as z:
                r=sample_crc(z,[i for i in z.infolist() if not i.is_dir()],time.monotonic()+5)
            self.assertGreater(r["crc_or_read_failures"]+r["crc_or_length_failures"],0)
        finally:t.cleanup()
    def test_header_census(self):
        t,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:
                r=sample_headers(z,z.infolist(),time.monotonic()+5)
            self.assertEqual(r["headers_sampled"],1)
        finally:t.cleanup()
    def test_source_report_privacy(self):
        t,p=self.fixture()
        try:
            expected={"selected_archive_summary":{"entries":2,
              "uncompressed_bytes":1402,"exe_count":1,"archive_bytes":p.stat().st_size}}
            report=inspect_zip(p,expected)
            self.assertNotIn(str(p),json.dumps(report))
            self.assertNotIn("car.modelbin",json.dumps(report))
            self.assertFalse(report["full_payload_crc_verified"])
        finally:t.cleanup()
    def test_crc_sample_not_full(self):
        t,p=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:r=sample_crc(z,z.infolist(),time.monotonic()+5)
            self.assertFalse(r["total_archive_payload_crc_verified"])
        finally:t.cleanup()
    def test_zip_magic(self):
        t,p=self.fixture()
        try:self.assertTrue(zip_magic(p))
        finally:t.cleanup()

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    trace=io.StringIO()
    tests=unittest.TextTestRunner(stream=trace,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (OUT/"M79_LOCAL_TESTS.txt").write_text(trace.getvalue(),encoding="utf8")
    if not tests.wasSuccessful():
        report={"stage":STAGE,"status":"M79_SELFTEST_FAILED"}
    else:
        prior=load_m78()
        if not prior:
            report={"stage":STAGE,"status":"M79_REQUIRES_M78_PUBLIC_REPORT"}
        else:
            matches=[p for p in candidate_paths() if metadata_match(p,prior)]
            if not matches:
                report={"stage":STAGE,"status":"M79_REQUIRES_LOCAL_M78_ARCHIVE",
                        "next_gate":"Run M78 on this phone again to recover the private local candidate path."}
            else:
                report=inspect_zip(matches[0],prior)
    (OUT/"M79_INTEGRITY_REPORT.json").write_text(
        json.dumps(report,indent=2)+"\n",encoding="utf8")
    (OUT/"M79_STATUS.txt").write_text(report["status"]+"\n",encoding="utf8")
    archive=OUT.parent/"FH5_M79_REPORTS.zip"
    with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
        for f in sorted(OUT.glob("M79_*")):
            if f.is_file() and f.suffix in (".json",".txt"):z.write(f,"FH5_M79/"+f.name)
    print("[M79]",report["status"])
    print("[M79] Public report:",archive)
    return 0 if report["status"]=="M79_SAMPLED_CRC_PASS_NO_FULL_INTEGRITY_CLAIM" else 17

if __name__ == "__main__":
    raise SystemExit(main())
