#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from patch_mesa_android_private_icd_exports import patch,ICD

VERSION_MAP = (
    "{\n\tglobal:\n"
    "\t\t# Android HAL entry\n"
    "\t\tHMI;\n\n"
    "\tlocal:\n"
    "\t\t# localize everything else\n"
    "\t\t*;\n};\n"
)
ANDROID_SYMBOLS = "# Android looks for HMI\nHMI\n"
NORMAL_MAP = ("{\n\tglobal:\n"+ "".join("\t\t"+k+";\n" for k in ICD)+
              "\tlocal:\n\t\t*;\n};\n")

class PrivateIcdExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.v=self.root/"src/vulkan"
        self.v.mkdir(parents=True)
        (self.v/"vulkan-android.sym").write_text(VERSION_MAP)
        (self.v/"vulkan-icd-android-symbols.txt").write_text(ANDROID_SYMBOLS)
        (self.v/"vulkan.sym").write_text(NORMAL_MAP)
    def tearDown(self): self.tmp.cleanup()
    def test_source_pinned_android_entrypoints_are_explicit(self):
        result=patch(self.root)
        after=(self.v/"vulkan-android.sym").read_text()
        symbol_list=(self.v/"vulkan-icd-android-symbols.txt").read_text()
        self.assertEqual(result["exported_symbols_expected"],list(ICD))
        for symbol in ICD:
            self.assertEqual(after.count(symbol+";"),1)
            self.assertEqual(symbol_list.splitlines().count(symbol),1)
        self.assertIn("\t\tHMI;",after)
        self.assertIn("\t\t*;",after)
        self.assertFalse(result["release_game_ready"])
    def test_reject_unknown_or_missing_android_hal_map(self):
        (self.v/"vulkan-android.sym").write_text(VERSION_MAP.replace("HMI;","HMI_REMOVED;"))
        with self.assertRaisesRegex(ValueError,"SOURCE_DRIFT"):
            patch(self.root)
    def test_reject_partial_prepatched_map(self):
        (self.v/"vulkan-android.sym").write_text(VERSION_MAP.replace(
            "HMI;","HMI;\n\t\t"+ICD[0]+";"))
        with self.assertRaisesRegex(ValueError,"PARTIAL_OR_PREPATCHED"):
            patch(self.root)
    def test_reject_unpinned_linux_source_abi(self):
        (self.v/"vulkan.sym").write_text(NORMAL_MAP.replace(ICD[1]+";",""))
        with self.assertRaisesRegex(ValueError,"NATIVE_ICD_EXPORT_SOURCE_MISSING"):
            patch(self.root)
    def test_no_partial_write_on_validation_failure(self):
        original=(self.v/"vulkan-android.sym").read_bytes()
        (self.v/"vulkan-icd-android-symbols.txt").write_text("invalid")
        with self.assertRaises(ValueError): patch(self.root)
        self.assertEqual((self.v/"vulkan-android.sym").read_bytes(),original)

if __name__=="__main__":unittest.main()
