"""Regression tests against a real GNU-built x86-64 PIE ELF fixture."""
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from kernix_elf64_fixture_check import check

SOURCE = Path(__file__).resolve().parents[1] / "native-engine/android-guest/kernix_elf64_guest_write_getpid.S"


class Elf64FixtureSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory(prefix="kernix-elf-fixture-") as temp:
            obj, guest=Path(temp)/"guest.o", Path(temp)/"guest.elf"
            subprocess.run(["as", "--64", str(SOURCE), "-o", str(obj)], check=True)
            subprocess.run([
                "ld","-pie","-nostdlib","--no-dynamic-linker",
                "--build-id=none","-z","max-page-size=0x4000",
                "-e","_start","-o",str(guest),str(obj)],check=True)
            cls.data=guest.read_bytes()
            cls.phoff=struct.unpack_from("<Q",cls.data,32)[0]
            cls.phnum=struct.unpack_from("<H",cls.data,56)[0]
            ph=[struct.unpack_from("<IIQQQQQQ",cls.data,cls.phoff+i*56)
                for i in range(cls.phnum)]
            cls.text=next(p for p in ph if p[0]==1 and p[1]==5)
            cls.rodata=next(p for p in ph if p[0]==1 and p[1]==4 and p[3]==0x8000)
            cls.dynamic=next(p for p in ph if p[0]==2)

    def test_valid_external_assembler_output(self):
        result=check(self.data)
        self.assertEqual(result["guest_syscalls"],[1,39])
        self.assertEqual(result["entry"],0x4000)
        self.assertTrue(result["relocation_free"])

    def test_rejects_truncated_elf_program_headers(self):
        with self.assertRaises(ValueError): check(self.data[:48])

    def test_rejects_tampered_machine(self):
        data=bytearray(self.data);struct.pack_into("<H",data,18,183)
        with self.assertRaises(ValueError): check(bytes(data))

    def test_rejects_wrong_elf_type(self):
        data=bytearray(self.data);struct.pack_into("<H",data,16,2)
        with self.assertRaises(ValueError): check(bytes(data))

    def test_rejects_guest_syscall_tampering(self):
        data=bytearray(self.data);data[self.text[2]+22]=0x90
        with self.assertRaises(ValueError): check(bytes(data))
        data=bytearray(self.data);data[self.text[2]+31]=0x90
        with self.assertRaises(ValueError): check(bytes(data))

    def test_rejects_modified_read_only_guest_message(self):
        data=bytearray(self.data);data[self.rodata[2]] ^= 1
        with self.assertRaises(ValueError):check(bytes(data))

    def test_rejects_added_dynamic_dependency(self):
        data=bytearray(self.data)
        # Change first dynamic tag from DT_HASH to DT_NEEDED=1.
        struct.pack_into("<q",data,self.dynamic[2],1)
        with self.assertRaises(ValueError):check(bytes(data))

    def test_rejects_unpinned_rw_load_virtual_address(self):
        data=bytearray(self.data)
        headers=[struct.unpack_from("<IIQQQQQQ",data,self.phoff+i*56)
                 for i in range(self.phnum)]
        rw_index=next(i for i,p in enumerate(headers) if p[0]==1 and p[1]==6)
        struct.pack_into("<Q",data,self.phoff+rw_index*56+16,0xff40)
        with self.assertRaises(ValueError): check(bytes(data))

    def test_rejects_changed_segment_permissions(self):
        data=bytearray(self.data)
        # Second PHDR is executable PT_LOAD; W+X is never allowed.
        struct.pack_into("<I",data,self.phoff+56+4,7)
        with self.assertRaises(ValueError):check(bytes(data))

    def test_rejects_wrong_program_header_count(self):
        data=bytearray(self.data);struct.pack_into("<H",data,56,8)
        with self.assertRaises(ValueError):check(bytes(data))


if __name__ == "__main__":
    unittest.main()
