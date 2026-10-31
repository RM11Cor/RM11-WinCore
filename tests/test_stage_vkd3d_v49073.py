import pathlib
import struct
import tempfile
import unittest
import sys
sys.path.insert(0, "tools")
from stage_vkd3d_v49073 import validate_pe64, find_x64

class TestPinnedVkd3dProvider(unittest.TestCase):
    def test_rejects_truncated_malformed_or_other_arch(self):
        with tempfile.TemporaryDirectory() as td:
            f=pathlib.Path(td)/"d3d12.dll"
            f.write_bytes(b"MZ"+bytes(8190))
            with self.assertRaises(ValueError):
                validate_pe64(f)
            data=bytearray(f.read_bytes())
            struct.pack_into("<I",data,0x3C,0x80)
            data[0x80:0x84]=b"PE\0\0"
            struct.pack_into("<H",data,0x84,0x14c)
            struct.pack_into("<H",data,0x98,0x20b)
            f.write_bytes(data)
            with self.assertRaises(ValueError):
                validate_pe64(f)
            struct.pack_into("<H",data,0x84,0x8664)
            f.write_bytes(data)
            validate_pe64(f)
    def test_only_resolves_x64_dll(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            (root/"x86").mkdir()
            (root/"x64").mkdir()
            (root/"x86/d3d12.dll").write_bytes(b"wrong")
            f=root/"x64/d3d12.dll"
            f.write_bytes(b"correct")
            self.assertEqual(find_x64(root,"d3d12.dll"),f)
if __name__=="__main__":
    unittest.main()
