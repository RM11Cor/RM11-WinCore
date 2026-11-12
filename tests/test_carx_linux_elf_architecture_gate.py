#!/usr/bin/env python3
"""Synthetic tests for Linux ELF CarX original AOT ABI gate, never game proof."""
from __future__ import annotations
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "carx_linux_gate",ROOT/"tools/carx_linux_elf_architecture_gate.py")
gate=importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(gate)

def elf64(machine=62,needed=("libc.so.6","libm.so.6"),endianness="<",corrupt_str=False):
    b=bytearray(1024)
    b[:4]=b"\x7fELF"
    b[4]=2
    b[5]=1 if endianness=="<" else 2
    b[6]=1
    struct.pack_into(endianness+"HHIQQQIHHHHHH",b,16,
        3,machine,1,0,64,0,0,64,56,2,0,0,0)
    struct.pack_into(endianness+"IIQQQQQQ",b,64,1,5,0,0x400000,0,len(b),len(b),4096)
    entries=[]
    strings=bytearray(b"\0")
    for name in needed:
        entries.append((1,len(strings)))
        strings.extend(name.encode("ascii")+b"\0")
    entries += [(5,0x401000 if corrupt_str else 0x400300),
                (10,len(strings)),(0,0)]
    off=0x100
    for i,(tag,val) in enumerate(entries):
        struct.pack_into(endianness+"QQ",b,off+i*16,tag,val)
    size=len(entries)*16
    struct.pack_into(endianness+"IIQQQQQQ",b,120,
        2,4,off,0x400100,0,size,size,8)
    b[0x300:0x300+len(strings)]=strings
    return bytes(b)

class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def store(self,content,filename="linux"):
        path=self.root/filename
        path.write_bytes(content)
        return path

    def test_linux_x86_64_glibc_cannot_dlopen_android(self):
        x=gate.inspect_file(self.store(elf64()))
        self.assertEqual(x["cpu_architecture"],"x86_64")
        self.assertIn("libc.so.6",x["shared_library_names"])
        self.assertTrue(x["glibc_or_gnucxx_dependency_detected"])
        self.assertFalse(x["original_linux_aarch64_machine_code_present"])
        self.assertFalse(x["android_bionic_abi_verified"])
        self.assertFalse(x["android_dlopen_succeeded"])

    def test_linux_aarch64_elf_not_automatically_android_bionic(self):
        x=gate.inspect_file(self.store(elf64(machine=183)))
        self.assertTrue(x["original_linux_aarch64_machine_code_present"])
        self.assertTrue(x["glibc_or_gnucxx_dependency_detected"])
        self.assertFalse(x["android_bionic_abi_verified"])
        self.assertFalse(x["original_carx_game_code_executed_on_android"])

    def test_linux_big_endian_metadata_detected(self):
        x=gate.inspect_file(self.store(elf64(endianness=">")))
        self.assertEqual(x["endianness"],"big")
        self.assertEqual(x["cpu_architecture"],"x86_64")

    def test_linux_elf_machine_arm32_no_64_native_gate(self):
        x=gate.inspect_file(self.store(elf64(machine=40)))
        self.assertEqual(x["cpu_architecture"],"ARM32")
        self.assertFalse(x["original_linux_aarch64_machine_code_present"])

    def test_both_linux_game_and_unity_arm64_still_not_android_port(self):
        for filename in ("GameAssembly.so","UnityPlayer.so"):
            self.store(elf64(machine=183),filename)
        d=gate.inspect_directory(self.root)
        self.assertTrue(d["original_linux_files_available"])
        self.assertTrue(d["linux_arm64_game_logic_and_unity_engine_both_proven"])
        self.assertFalse(d["android_game_abi_and_native_code_verified"])
        self.assertFalse(d["original_android_game_logic_present"])
        self.assertFalse(d["original_game_frame_presented"])

    def test_both_linux_game_and_unity_x86_gate_false(self):
        for filename in ("GameAssembly.so","UnityPlayer.so"):
            self.store(elf64(),filename)
        d=gate.inspect_directory(self.root)
        self.assertTrue(d["original_linux_files_available"])
        self.assertFalse(d["linux_arm64_game_logic_and_unity_engine_both_proven"])

    def test_game_only_no_unity_engine_gate_false(self):
        self.store(elf64(machine=183),"GameAssembly.so")
        d=gate.inspect_directory(self.root)
        self.assertFalse(d["original_linux_files_available"])
        self.assertFalse(d["linux_arm64_game_logic_and_unity_engine_both_proven"])

    def test_no_original_linux_sources_never_claim_success(self):
        d=gate.inspect_directory(self.root)
        self.assertFalse(d["original_linux_files_available"])
        self.assertFalse(d["linux_arm64_game_logic_and_unity_engine_both_proven"])

    def test_fake_windows_pe_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"MZ"+bytes(1024)))

    def test_fake_macho_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"\xcf\xfa\xed\xfe"+bytes(1024)))

    def test_reject_elf32_masquerading_as_android(self):
        fake=bytearray(elf64(machine=183))
        fake[4]=1
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(fake))

    def test_reject_corrupt_program_header_count(self):
        fake=bytearray(elf64())
        struct.pack_into("<H",fake,56,8192)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(fake))

    def test_reject_strtab_not_in_original_load_segment(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(elf64(corrupt_str=True)))

    def test_reject_needed_offset_outside_strtab(self):
        fake=bytearray(elf64())
        struct.pack_into("<Q",fake,0x100+8,4096)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(fake))

    def test_reject_symlink(self):
        p=self.store(elf64())
        s=self.root/"linked"
        s.symlink_to(p)
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(s)

    def test_reject_tiny_elf(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_file(self.store(b"\x7fELF"+bytes(11)))

if __name__=="__main__":
    unittest.main(verbosity=2)
