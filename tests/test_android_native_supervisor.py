#!/usr/bin/env python3
"""Synthetic ELF64 tests, no Android device or user games."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_android_native_supervisor import audit_bytes, audit


def binary(machine=183, elf_type=3, interpreter=b"/system/bin/linker64\x00",
           alignment=16384):
    data=bytearray(4096)
    data[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, elf_type, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 2)
    # One PT_LOAD plus a PT_INTERP.
    struct.pack_into("<I", data, 64, 1)
    struct.pack_into("<Q", data, 64+8, 0)
    struct.pack_into("<Q", data, 64+32, len(data))
    struct.pack_into("<Q", data, 64+48, alignment)
    struct.pack_into("<I", data, 120, 3)
    struct.pack_into("<Q", data, 120+8, 0x800)
    struct.pack_into("<Q", data, 120+32, len(interpreter))
    data[0x800:0x800+len(interpreter)] = interpreter
    return bytes(data)


class AndroidNativeSupervisorTests(unittest.TestCase):
    def test_aarch64_pie_with_android_linker_is_structure_ready(self):
        value=audit_bytes(binary())
        self.assertEqual(value["status"],
                         "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF")
        self.assertFalse(value.get("safe_to_activate_engine", False))

    def test_x86_linux_binary_cannot_be_mistaken_for_android(self):
        self.assertEqual(audit_bytes(binary(machine=62))["status"],"BLOCKED")

    def test_non_pie_image_rejected(self):
        self.assertEqual(audit_bytes(binary(elf_type=2))["status"],"BLOCKED")

    def test_glibc_interpreter_rejected(self):
        self.assertEqual(audit_bytes(binary(interpreter=b"/lib/ld-linux-aarch64.so.1\x00"))["status"],
                         "BLOCKED")

    def test_unaligned_load_segment_rejected(self):
        self.assertEqual(audit_bytes(binary(alignment=4096))["status"],"BLOCKED")

    def test_truncated_program_header_does_not_pass(self):
        self.assertEqual(audit_bytes(binary()[:100])["status"],"BLOCKED")

    def test_apk_library_name_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"rm11_supervisor.bin"
            path.write_bytes(binary())
            self.assertEqual(audit(path)["status"],"BLOCKED")
            named=Path(tmp)/"librm11_engine_supervisor.so"
            named.write_bytes(binary())
            self.assertEqual(audit(named)["status"],
                             "ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF")
            self.assertEqual(audit(named)["android_executable_test"],"NOT_PERFORMED")
            self.assertFalse(audit(named)["safe_to_activate_engine"])


if __name__=="__main__":
    unittest.main()
