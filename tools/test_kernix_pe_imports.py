"""Synthetic PE import tests — no games and no executable launch."""
import struct
import tempfile
import unittest
from pathlib import Path
from kernix_pe_imports import analyze

def sample(dll=b"d3d11.dll"):
    b=bytearray(1024)
    b[:2]=b"MZ"
    struct.pack_into("<I",b,0x3c,128)
    b[128:132]=b"PE"+bytes(2)
    struct.pack_into("<HHIIIHH",b,132,0x8664,1,0,0,0,240,0x22)
    opt=152
    struct.pack_into("<H",b,opt,0x20b)
    struct.pack_into("<I",b,opt+60,512)
    struct.pack_into("<II",b,opt+120,0x1000,40)
    section=opt+240
    struct.pack_into("<IIII",b,section+8,512,0x1000,512,512)
    struct.pack_into("<IIIII",b,512,0,0,0,0x1080,0)
    b[640:640+len(dll)+1]=dll+bytes(1)
    return bytes(b)

class ImportTest(unittest.TestCase):
    def test_d3d11(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"demo.exe";p.write_bytes(sample())
            x=analyze(p)
            self.assertIn("d3d11.dll",x["static_imports"])
            self.assertIn("Direct3D 11",x["graphics_api_indicators"])
            self.assertTrue(x["dynamic_imports_not_detected"])
    def test_vulkan(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"demo.exe";p.write_bytes(sample(b"vulkan-1.dll"))
            self.assertIn("Vulkan loader",analyze(p)["graphics_api_indicators"])
    def test_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"broken.exe";p.write_bytes(sample()[:200])
            with self.assertRaises(ValueError):analyze(p)
    def test_no_execution_and_no_fake_fps(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"demo.exe";p.write_bytes(sample(b"dxgi.dll"))
            result=analyze(p)
            self.assertNotIn("Direct3D 11",result["graphics_api_indicators"])
            self.assertEqual(result["recommendation"],"No component selection without full compatibility registry and runtime evidence")

if __name__=="__main__":unittest.main()
