#!/usr/bin/env python3
"""Compare genuine x86-64 native calls and statically recompiled ARM64 Linux.

We use synthetic Windows ABI function bodies; real CarX remains a separate
next-step gate. AArch64 QEMU is used only in CI as a test runner, NOT as a
required game runtime on the phone.
"""
from __future__ import annotations
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
MODULE=REPO/"native-port/recompiler/x64_function_aot.py"
spec=importlib.util.spec_from_file_location("aot_x64",MODULE)
aot=importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules[spec.name]=aot
spec.loader.exec_module(aot)

PROGRAMS={
    "add_xor":"""
        mov rax, rcx
        add rax, rdx
        xor rax, r8
        ret
""",
    "unsigned_branch":"""
        mov rax, rcx
        cmp rax, rdx
        jae .Lgreater
        mov rax, rdx
        jmp .Lend
.Lgreater:
        sub rax, rdx
.Lend:
        ret
""",
    "signed_branch":"""
        mov rax, rcx
        cmp rax, rdx
        jge .Lge
        mov rax, rdx
        ret
.Lge:
        sub rax, rdx
        ret
""",
    "memory_stack":"""
        sub rsp, 40
        mov qword ptr [rsp+8], rcx
        mov rax, qword ptr [rsp+8]
        add rax, rdx
        add rsp, 40
        ret
""",
    "local_call":"""
        call .Lhelper
        xor rax, r8
        ret
.Lhelper:
        mov rax, rcx
        add rax, rdx
        ret
""",
    "test_branch":"""
        mov rax, rcx
        test rax, rax
        je .Lzero
        sub rax, rdx
        ret
.Lzero:
        mov rax, r8
        ret
""",
    "push_pop":"""
        push rcx
        pop rax
        add rax, rdx
        ret
""",
    "lea":"""
        mov rax, rcx
        lea rax, [rax+16]
        ret
""",
}
CASES=[
    [0,0,0,0],
    [1,2,3,4],
    [9,3,7,1],
    [0,45,99,3],
    [0xffffffffffffffff,1,0,0],
    [0x7fffffffffffffff,0x8000000000000000,0x13579bdf,5],
    [0x8000000000000000,0x7fffffffffffffff,8,11],
    [0xffffffffffffffff,0xffffffffffffffff,0x10000,2],
    [0x123456789abcde,0xfedcba987654321,0x1000,100],
    [100,200,300,400],
]

DRIVER=r"""
#include <cstdint>
#include <cstdlib>
#include <iostream>
extern "C" uint64_t guest_fn(uint64_t a,uint64_t b,uint64_t c,uint64_t d)
    __attribute__((ms_abi));
int main(int argc,char** argv) {
    if(argc!=5)return 2;
    std::cout<<guest_fn(strtoull(argv[1],nullptr,0),
                         strtoull(argv[2],nullptr,0),
                         strtoull(argv[3],nullptr,0),
                         strtoull(argv[4],nullptr,0))<<"\n";
}
"""

class SourceRecompilerPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for binary in ["gcc","g++","objcopy","aarch64-linux-gnu-g++","qemu-aarch64"]:
            if shutil.which(binary) is None:
                raise RuntimeError("CI requires installed real cross architecture tool "+binary)
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        (cls.root/"driver.cpp").write_text(DRIVER,encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_checked(self,args,**kw):
        result=subprocess.run([str(x) for x in args],text=True,
                              capture_output=True,**kw)
        if result.returncode!=0:
            raise AssertionError(
                "failed command %s\nstdout %s\nstderr %s"%
                (args,result.stdout[-3000:],result.stderr[-3000:]))
        return result.stdout.strip()

    def compile_case(self,key,body):
        directory=self.root/key
        directory.mkdir(exist_ok=True)
        src=directory/"source.S"
        src.write_text(
            ".intel_syntax noprefix\n"
            ".text\n"
            ".global guest_fn\n"
            ".type guest_fn,@function\n"
            "guest_fn:\n"+body+"\n",encoding="utf-8")
        obj=directory/"source.o"
        original=directory/"original"
        raw=directory/"original.bin"
        self.run_checked(["gcc","-c",src,"-o",obj])
        self.run_checked(["objcopy","-j",".text","-O","binary",obj,raw])
        self.run_checked(["g++","-O2",self.root/"driver.cpp",obj,"-o",original])
        lifted=aot.lift_function(raw.read_bytes())
        self.assertGreater(lifted.insn_count,1)
        cpp=directory/"recompiled.cpp"
        cpp.write_text(lifted.code,encoding="utf-8")
        arm=directory/"recompiled_aarch64"
        self.run_checked(["aarch64-linux-gnu-g++","-static","-O2",cpp,"-o",arm])
        header=self.run_checked(["readelf","-h",arm])
        self.assertIn("AArch64",header)
        return original,arm,lifted

    def test_actual_x86_against_native_aarch64_aot_for_8_programs_80_cases(self):
        results={}
        for key,body in PROGRAMS.items():
            with self.subTest(program=key):
                original,arm,lifted=self.compile_case(key,body)
                for args in CASES:
                    with self.subTest(args=args):
                        nums=[str(n) for n in args]
                        reference=self.run_checked([original,*nums])
                        native=self.run_checked(["qemu-aarch64",arm,*nums])
                        self.assertEqual(native,reference)
                results[key]=lifted.insn_count
        print("CARX_AOT_X64_WINDOWS_ABI_TO_NATIVE_AARCH64_RESULTS="+str(results))
        print("CARX_AOT_8_WINDOWS_ABI_PROGRAMS_80_BEHAVIORAL_COMPARISONS_PASS")

    def test_reject_unhandled_sse_instruction(self):
        # addss xmm0,xmm1
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("f3 0f 58 c1 c3"))

    def test_reject_unknown_indirect_branch(self):
        # jmp rax
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("ff e0 c3"))

    def test_reject_external_call(self):
        # call far beyond this function bytes
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("e8 01 00 00 00 c3"))

    def test_reject_incomplete_instruction(self):
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("48 c7"))

    def test_reject_no_return(self):
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("90 90 90"))

    def test_reject_32_bit_register_write_until_semantics_added(self):
        # mov eax, ecx; ret
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(bytes.fromhex("89 c8 c3"))

    def test_reject_missing_function(self):
        with self.assertRaises(aot.UnsupportedGuestCode):
            aot.lift_function(b"")

    def test_no_x86_dynamic_decoder_in_generated_arm64_source(self):
        src=aot.lift_function(bytes.fromhex("48 89 c8 c3")).code
        self.assertNotIn("capstone",src.lower())
        self.assertNotIn("libfex",src.lower())
        self.assertNotIn("wine",src.lower())
        self.assertIn("static uint64_t run",src)
        self.assertIn("Windows x64 ABI",src)

if __name__=="__main__":
    unittest.main(verbosity=2)
