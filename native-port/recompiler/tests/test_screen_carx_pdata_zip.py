#!/usr/bin/env python3
"""Synthetic bridge-package validation (never actual copyrighted game code)."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

FOLDER=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(FOLDER))
import screen_carx_pdata_zip as screen

class SampleArchiveValidation(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def make_zip(self,wrong_hash=False,duplicate=False):
        correct=bytes.fromhex("48 89 c8 48 01 d0 c3")
        unsupported=bytes.fromhex("f3 0f 58 c1 c3")
        functions=[]
        path=self.root/"samples.zip"
        with zipfile.ZipFile(path,"w") as z:
            for rva,body in ((0x1000,correct),(0x1200,unsupported)):
                member="code/rva_%08x.bin"%rva
                functions.append({
                    "relative_rva":rva,"length_bytes":len(body),
                    "zip_member":member,
                    "sha256":("x"*64 if wrong_hash else hashlib.sha256(body).hexdigest())
                })
                z.writestr(member,body)
            if duplicate:
                z.writestr("code/rva_00001000.bin",correct)
            z.writestr("manifest.json",json.dumps({
                "schema":"rm11carx.original-win64-gameassembly-bounded-function-samples.v1",
                "functions":functions
            }))
        return path

    def test_real_machine_byte_screen_generates_only_supported_cpp(self):
        report=screen.screen(self.make_zip(),self.root/"output")
        self.assertEqual(report["original_function_samples_examined"],2)
        self.assertEqual(report["aot_supported_source_functions"],1)
        self.assertEqual(report["aot_rejected_source_functions"],1)
        self.assertFalse(report["android_aarch64_carx_gameplay_executed"])
        self.assertEqual(len(list((self.root/"output").glob("*.cpp"))),1)

    def test_bad_sha_refused(self):
        with self.assertRaises(ValueError):
            screen.screen(self.make_zip(wrong_hash=True))

    def test_duplicate_archive_entries_refused(self):
        with self.assertRaises(ValueError):
            screen.screen(self.make_zip(duplicate=True))

    def test_no_overwriting_previously_generated_cpp(self):
        path=self.make_zip()
        output=self.root/"output"
        screen.screen(path,output)
        with self.assertRaises(ValueError):
            screen.screen(path,output)

if __name__=="__main__":
    unittest.main(verbosity=2)
