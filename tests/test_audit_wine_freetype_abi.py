import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location(
    "audit",Path(__file__).parent.parent/"tools/audit_wine_freetype_abi.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestSignatureExtractor(unittest.TestCase):
    def test_finds_null_terminated_names_only(self):
        data=b"\x00FT_Init_FreeType\x00 FT_Load_Glyph\x00FT_Whatever\x00"
        self.assertIn("FT_Init_FreeType",module.expected_wine_functions(data))
        self.assertIn("FT_Load_Glyph",module.expected_wine_functions(data))
        self.assertNotIn("FT_Bad",module.expected_wine_functions(data))
    def test_requires_aarch64_elf(self):
        with self.assertRaises(ValueError):
            module.arm64_elf(b"random","test")
    def test_never_calls_native_library(self):
        self.assertFalse(hasattr(module,"load_library"))


if __name__=="__main__":
    unittest.main()
