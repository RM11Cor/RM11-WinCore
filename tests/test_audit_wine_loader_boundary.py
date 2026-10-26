import importlib.util
from pathlib import Path
import unittest

src=Path(__file__).resolve().parent.parent/"tools/audit_wine_loader_boundary.py"
spec=importlib.util.spec_from_file_location("linker",src)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ELFLinkerTests(unittest.TestCase):
    def test_reads_soname_and_needed(self):
        lines=" 0x0001 (NEEDED) Shared library: [libc.so]\n 0x000e (SONAME) Library soname: [libfreetype.so]\n"
        self.assertEqual(m.needed_from_readelf(lines),["libc.so"])
        self.assertEqual(m.soname_from_readelf(lines),"libfreetype.so")
    def test_recognizes_unresolved_dynamic_import(self):
        values="""   12: 000000000000  0 FUNC GLOBAL DEFAULT UND dlopen
   15: 000000000100  16 FUNC GLOBAL DEFAULT   15 FT_Init_FreeType
"""
        im,ex=m.symbols_from_readelf(values)
        self.assertIn("dlopen",im)
        self.assertIn("FT_Init_FreeType",ex)
    def test_default_font_redirect_disabled(self):
        s='env.put("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT", "0");\nenv.put("LD_PRELOAD", p.apkNativeLibs.resolve("librm11_wine_data_redirect.so").toString());'
        x=m.loader_environment(s)
        self.assertTrue(x["source_freetype_redirect_defaults_off"])
        self.assertTrue(x["source_preloads_native_redirect_shim"])
    def test_refuses_wrong_elf(self):
        with self.assertRaises(ValueError):
            m.arm64_elf(b"MZ"+b"x"*1200,"non-elf")


if __name__ == "__main__":
    unittest.main()
