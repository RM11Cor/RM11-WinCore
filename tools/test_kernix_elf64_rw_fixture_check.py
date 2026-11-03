"""KERNIX independent as/ld ELF64 RW guest negative integrity tests."""
from __future__ import annotations
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from kernix_elf64_rw_fixture_check import check

SOURCE = Path(__file__).resolve().parents[1] / "native-engine/android-guest/kernix_elf64_rw_guest.S"

class GuestWritableELFRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp:
            o=Path(temp)/"guest.o"
            e=Path(temp)/"guest.elf"
            subprocess.run(["as","--64",str(SOURCE),"-o",str(o)],check=True)
            subprocess.run(["ld","-pie","-nostdlib","--no-dynamic-linker",
                "--build-id=none","-z","max-page-size=0x4000","-z","norelro",
                "-e","_start","-o",str(e),str(o)],check=True)
            cls.original=e.read_bytes()
        phoff=struct.unpack_from("<Q",cls.original,32)[0]
        cls.phoff=phoff
        cls.loads=[struct.unpack_from("<IIQQQQQQ",cls.original,phoff+i*56)
                   for i in range(4)]
        cls.dynamic=struct.unpack_from("<IIQQQQQQ",cls.original,phoff+4*56)

    def assertRejected(self, updated: bytes):
        with self.assertRaises(ValueError):
            check(updated)

    def test_compiled_original_passes(self):
        info=check(self.original)
        self.assertEqual(info["guest_syscalls"],[1,39])
        self.assertEqual(info["message_length"],26)

    def test_modified_guest_instruction_fails(self):
        b=bytearray(self.original)
        b[self.loads[1][2]+19]^=1  # REP MOVSB opcode
        self.assertRejected(bytes(b))

    def test_changed_writable_rip_pointer_fails(self):
        b=bytearray(self.original)
        b[self.loads[1][2]+10]^=1
        self.assertRejected(bytes(b))

    def test_tampered_guest_readonly_template_fails(self):
        b=bytearray(self.original)
        b[self.loads[2][2]]^=1
        self.assertRejected(bytes(b))

    def test_nonzero_guest_writable_data_fails(self):
        b=bytearray(self.original)
        b[self.loads[3][2]+self.dynamic[5]]^=1
        self.assertRejected(bytes(b))

    def test_wx_guest_segment_fails(self):
        b=bytearray(self.original)
        b[self.phoff+3*56+4]=7
        self.assertRejected(bytes(b))

    def test_interpreter_or_dynamic_dependency_fails(self):
        b=bytearray(self.original)
        struct.pack_into("<I",b,self.phoff+5*56,3) # PT_INTERP
        self.assertRejected(bytes(b))
        b=bytearray(self.original)
        struct.pack_into("<q",b,self.dynamic[2],1) # DT_NEEDED
        self.assertRejected(bytes(b))

    def test_wrong_machine_and_truncation_fail(self):
        b=bytearray(self.original)
        struct.pack_into("<H",b,18,183)  # ARM64, not x86-64
        self.assertRejected(bytes(b))
        self.assertRejected(self.original[:64])

if __name__ == "__main__":
    unittest.main()
