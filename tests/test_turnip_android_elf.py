#!/usr/bin/env python3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_turnip_android_elf import validate


def fake_elf(machine=183,typ=3):
    data=bytearray(4096)
    data[:6]=b"\x7fELF\x02\x01"
    struct.pack_into("<HH",data,16,typ,machine)
    return bytes(data)


class TurnipAbiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/"libvulkan_freedreno.so"
        self.path.write_bytes(fake_elf())
    def tearDown(self):
        self.temp.cleanup()

    def test_bionic_aarch64_shared_elf_still_not_proof_of_gpu_presentation(self):
        dynamic=" 0x0000000000000001 (NEEDED) Shared library: [libc.so]\n"
        result=validate(self.path,dynamic)
        self.assertTrue(result["static_elf_abi_verified"])
        self.assertFalse(result["actual_adreno_hardware_frame_presented"])
        self.assertFalse(result["safe_to_publish_engine_apk"])

    def test_glibc_host_driver_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"GLIBC_BINARY"):
            validate(self.path,"(NEEDED) Shared library: [libc.so.6]\n")

    def test_wrong_amd64_architecture_is_rejected(self):
        self.path.write_bytes(fake_elf(machine=62))
        with self.assertRaisesRegex(ValueError,"NOT_AARCH64"):
            validate(self.path,"(NEEDED) Shared library: [libc.so]\n")

    def test_non_shared_executable_is_rejected(self):
        self.path.write_bytes(fake_elf(typ=2))
        with self.assertRaisesRegex(ValueError,"NOT_AARCH64_ET_DYN"):
            validate(self.path,"(NEEDED) Shared library: [libc.so]\n")

    def test_no_bionic_libc_evidence_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"BIONIC_LIBC_DEPENDENCY"):
            validate(self.path,"(NEEDED) Shared library: [libm.so]\n")


if __name__=="__main__":
    unittest.main()
