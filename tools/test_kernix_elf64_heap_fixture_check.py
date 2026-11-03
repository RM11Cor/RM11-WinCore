"""Independent GNU ELF64 x86 guest heap+four syscall negative tests."""
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from kernix_elf64_heap_fixture_check import check

SOURCE=Path(__file__).resolve().parents[1]/"native-engine/android-guest/kernix_elf64_heap_syscalls_guest.S"
class HeapELFFixtureNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            obj=Path(d)/"guest.o";binary=Path(d)/"guest.elf"
            subprocess.run(["as","--64",str(SOURCE),"-o",str(obj)],check=True)
            subprocess.run(["ld","-pie","-nostdlib","--no-dynamic-linker",
                "--build-id=none","-z","max-page-size=0x4000","-z","norelro",
                "-e","_start","-o",str(binary),str(obj)],check=True)
            cls.valid=binary.read_bytes()
        cls.phoff=struct.unpack_from("<Q",cls.valid,32)[0]
        cls.text=struct.unpack_from("<IIQQQQQQ",cls.valid,cls.phoff+56)
        cls.rodata=struct.unpack_from("<IIQQQQQQ",cls.valid,cls.phoff+112)
        cls.dynamic=struct.unpack_from("<IIQQQQQQ",cls.valid,cls.phoff+224)

    def test_real_assembled_guest(self):
        record=check(self.valid)
        self.assertEqual(record["four_guest_linux_syscalls"],[9,1,39,11])
        self.assertEqual(record["guest_code_bytes"],115)

    def test_rejects_tampered_mmap_syscall(self):
        for offset in (39,79,88,106):
            buf=bytearray(self.valid)
            buf[self.text[2]+offset] ^= 0x2
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(bytes(buf))

    def test_rejects_tampered_low_register_shadow(self):
        for offset in (33,34,35,36,37,38):
            buf=bytearray(self.valid)
            buf[self.text[2]+offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(bytes(buf))

    def test_rejects_wrong_mapping_arguments(self):
        for offset in (9,13,21,27):
            buf=bytearray(self.valid)
            buf[self.text[2]+offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(bytes(buf))

    def test_rejects_changed_read_only_message(self):
        buf=bytearray(self.valid)
        buf[self.rodata[2]]^=1
        with self.assertRaises(ValueError):check(bytes(buf))

    def test_rejects_unexpected_dynamic_dependency(self):
        buf=bytearray(self.valid)
        struct.pack_into("<q",buf,self.dynamic[2],1) # DT_NEEDED
        with self.assertRaises(ValueError):check(bytes(buf))

    def test_rejects_executable_guest_data(self):
        buf=bytearray(self.valid)
        buf[self.phoff+3*56+4]=7
        with self.assertRaises(ValueError):check(bytes(buf))

    def test_rejects_non_elf_wrong_cpu_and_truncation(self):
        for offset in (0,4,16,18,56):
            buf=bytearray(self.valid)
            buf[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(bytes(buf))
        with self.assertRaises(ValueError):check(self.valid[:30])

if __name__=="__main__":
    unittest.main()
