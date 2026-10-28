#!/usr/bin/env python3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_turnip_android_elf import validate,verify_exported_icd,REQUIRED_ICD_EXPORTS


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

    def test_real_public_icd_functions_are_required(self):
        lines=[]
        for index,name in enumerate(REQUIRED_ICD_EXPORTS,1):
            lines.append(f" {index}: 0000000000010000  24 FUNC GLOBAL DEFAULT 14 {name}")
        r=verify_exported_icd("\n".join(lines))
        self.assertTrue(r["icd_public_elf_symbols_verified"])
        self.assertEqual(len(r["icd_exported_functions"]),3)
        with self.assertRaisesRegex(ValueError,"PUBLIC_SYMBOL_MISSING"):
            verify_exported_icd("\n".join(lines[:-1]))
        with self.assertRaisesRegex(ValueError,"PUBLIC_SYMBOL_MISSING"):
            verify_exported_icd("\n".join(x.replace("GLOBAL","LOCAL") for x in lines))
        with self.assertRaisesRegex(ValueError,"PUBLIC_SYMBOL_MISSING"):
            verify_exported_icd("\n".join(x.replace("DEFAULT 14","DEFAULT UND") for x in lines))

    def test_bionic_aarch64_shared_elf_still_not_proof_of_gpu_presentation(self):
        dynamic=" 0x0000000000000001 (NEEDED) Shared library: [libc.so]\n"
        result=validate(self.path,dynamic)
        self.assertTrue(result["static_elf_abi_verified"])
        self.assertFalse(result["actual_adreno_hardware_frame_presented"])
        self.assertFalse(result["safe_to_publish_engine_apk"])

    def test_private_hal_libhardware_blocks_unverified_app_namespace(self):
        dynamic=("(NEEDED) Shared library: [libc.so]\n"
                 "(NEEDED) Shared library: [libhardware.so]\n")
        r=validate(self.path,dynamic)
        self.assertEqual(r["app_linker_namespace_gate"],
                         "BLOCKED_PRIVATE_AOSP_LIBHARDWARE_DEPENDENCY")
        self.assertFalse(r["app_native_dlopen_succeeded"])

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
