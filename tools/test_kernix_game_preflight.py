#!/usr/bin/env python3
"""Tiny synthetic PE test fixtures: no copyrighted games and no execution."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from kernix_game_preflight import inspect

def make_pe(machine=0x8664, subsystem=2, magic=0x20b):
    data=bytearray(512)
    data[:2]=b"MZ"
    struct.pack_into("<I",data,0x3c,128)
    data[128:132]=b"PE"+bytes(2)
    struct.pack_into("<HHIIIHH",data,132,machine,1,0,0,0,80,0x22)
    struct.pack_into("<H",data,152,magic)
    struct.pack_into("<H",data,152+68,subsystem)
    return bytes(data)

class SafePreflight(unittest.TestCase):
    def test_x64(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"demo.exe"
            p.write_bytes(make_pe())
            r=inspect(p)
            self.assertEqual(r["architecture"],"x86_64")
            self.assertEqual(r["subsystem"],"windows_gui")
            self.assertEqual(r["sha256"],hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertFalse(r["runtime_tested"])
    def test_x86(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"demo.exe"
            p.write_bytes(make_pe(machine=0x14c,magic=0x10b))
            self.assertEqual(inspect(p)["architecture"],"x86")
    def test_reject_bad_header(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"broken.exe"
            p.write_bytes(b"invalid")
            with self.assertRaises(ValueError):
                inspect(p)
    def test_reject_truncated_pe(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"broken.exe"
            p.write_bytes(make_pe()[:145])
            with self.assertRaises(ValueError):
                inspect(p)

if __name__=="__main__":
    unittest.main()
