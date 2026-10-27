#!/usr/bin/env python3
"""Host tests for safe read-only pinned release runtime staging."""
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_pinned_legacy_runtime import stage,PINNED_FILES


def checksum(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


class StageLegacyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.repo=self.root/"repo"
        self.repo.mkdir()
        self.apk=self.root/"published.apk"
        self.content={name:(b"MZ-"+name.encode() if name.endswith(".zip")
                            else b"\x7fELF-"+name.encode())
                      for name in PINNED_FILES}
        self.make_apk()

    def tearDown(self):
        self.temp.cleanup()

    def make_apk(self,exclude=None):
        with zipfile.ZipFile(self.apk,"w") as output:
            for name,data in self.content.items():
                if name!=exclude:
                    output.writestr(name,data)

    def test_exact_pinned_entries_and_byte_identity(self):
        manifest=stage(self.apk,self.repo,checksum(self.apk))
        self.assertFalse(manifest["complete_windows_game_engine"])
        self.assertFalse(manifest["published_apk"])
        for name,target in PINNED_FILES.items():
            self.assertEqual((self.repo/target).read_bytes(),self.content[name])
            self.assertEqual(manifest["pinned_runtime_components"][name]["sha256"],
                             hashlib.sha256(self.content[name]).hexdigest())

    def test_digest_mismatch_blocks_all_writes(self):
        with self.assertRaisesRegex(ValueError,"SHA_MISMATCH"):
            stage(self.apk,self.repo,"0"*64)
        for p in PINNED_FILES.values():
            self.assertFalse((self.repo/p).exists())

    def test_missing_native_loader_aborts_before_extraction(self):
        self.make_apk(exclude="lib/arm64-v8a/libwineprobe.so")
        with self.assertRaisesRegex(ValueError,"MISSING_OR_DUPLICATED"):
            stage(self.apk,self.repo,checksum(self.apk))

    def test_existing_native_file_never_overwritten(self):
        target=self.repo/PINNED_FILES["lib/arm64-v8a/libwineprobe.so"]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"existing-user-data")
        with self.assertRaisesRegex(ValueError,"NOT_CLEAN"):
            stage(self.apk,self.repo,checksum(self.apk))
        self.assertEqual(target.read_bytes(),b"existing-user-data")


if __name__=="__main__":
    unittest.main()
