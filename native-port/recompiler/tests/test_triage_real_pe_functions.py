#!/usr/bin/env python3
"""Synthetic x64 machine-code ZIP only; user game code never in CI."""
from __future__ import annotations
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import triage_real_pe_functions as analyzer

class TestOriginalPeTriage(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def create(self,tamper=False,duplicate=False):
        # Compiler/assembler-style x64 synthetic functions only.
        fixtures={
            0x1000:bytes.fromhex("48 89 c8 48 01 d0 c3"), # mov/add/ret
            0x2000:bytes.fromhex("e8 00 00 01 00 c3"), # external call
            0x3000:bytes.fromhex("48 8b 05 00 00 00 00 c3"), # RIP relative mov
            0x4000:bytes.fromhex("0f 28 c1 c3"), # movaps xmm0,xmm1
            0x5000:bytes.fromhex("48 83 c4 20 5b c3"), # ADD RSP POP RET epilogue
        }
        path=self.root/"synthetic.zip"
        items=[]
        with zipfile.ZipFile(path,"w") as z:
            for i,(rva,code) in enumerate(fixtures.items()):
                member="code/rva_%08x.bin"%rva
                z.writestr(member,code)
                digest=hashlib.sha256(code).hexdigest()
                items.append({
                    "relative_rva":rva,
                    "length_bytes":len(code),
                    "zip_member":member,
                    "sha256":"0"*64 if tamper and i==0 else digest,
                })
            if duplicate:
                z.writestr("code/rva_00001000.bin",fixtures[0x1000])
            z.writestr("manifest.json",json.dumps({
                "schema":analyzer.SOURCE_SCHEMA,
                "source_file_size_bytes":142049792,
                "total_exception_table_entries":412001,
                "functions":items,
            }))
        return path

    def test_real_observability_categories_on_synthetic_samples(self):
        r=analyzer.triage(self.create())
        self.assertEqual(r["samples_examined_and_hashes_verified"],5)
        self.assertEqual(r["categories"]["external_call_target"],1)
        self.assertEqual(r["categories"]["rip_relative_memory"],1)
        self.assertEqual(r["categories"]["simd_or_vector"],1)
        self.assertEqual(r["categories"]["possible_epilogue_or_chained_pdata_region"],1)
        self.assertFalse(r["actual_carx_gameplay_execution_proven"])
        self.assertNotIn("raw_bytes",r)
        self.assertNotIn("machine_code",r)

    def test_reject_tampered_original_source_hash(self):
        with self.assertRaises(ValueError):
            analyzer.triage(self.create(tamper=True))

    def test_reject_ambiguous_duplicate_code_archive_member(self):
        with self.assertRaises(ValueError):
            analyzer.triage(self.create(duplicate=True))

    def test_reject_nonexistent_zip(self):
        with self.assertRaises(ValueError):
            analyzer.triage(self.root/"missing.zip")

if __name__=="__main__":
    unittest.main(verbosity=2)
