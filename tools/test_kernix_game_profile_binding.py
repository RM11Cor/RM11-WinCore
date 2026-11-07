"""Synthetic offline profile-to-real-file binding; no game binaries or runtime."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from kernix_game_profile_binding import bind


def pe(machine=0x8664, magic=0x20b):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I",data,0x3c,128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH",data,132,machine,1,0,0,0,80,0x22)
    struct.pack_into("<H",data,152,magic)
    struct.pack_into("<H",data,152+68,2)
    return bytes(data)


class ExactProfileBinding(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.exe=self.root/"test.exe"
        self.exe.write_bytes(pe())
        self.registry={"schema":"kernix.component-registry.v1","components":[]}
        self.profile={"schema":"kernix.game-profile.v1",
                      "game_sha256":hashlib.sha256(self.exe.read_bytes()).hexdigest(),
                      "mode":"balanced","components":{},"enabled":False}

    def test_identical_image_accepts_identity_only(self):
        result=bind(self.profile,self.registry,self.exe)
        self.assertEqual(result["profile_binding"],"exact-file-hash-verified-static-only")
        self.assertEqual(result["game_image_format"],"windows-pe32+-x86_64")
        for denied in ("profile_enabled","launch_qualified","guest_code_executed",
                       "game_files_modified","binary_patches_applied","android_device_tested"):
            self.assertFalse(result[denied])
        self.assertEqual(self.exe.read_bytes(),pe())

    def test_tampered_game_hash_rejected(self):
        self.exe.write_bytes(pe()+b"modified")
        with self.assertRaisesRegex(ValueError,"EXACT_GAME_EXECUTABLE_SHA256_MISMATCH"):
            bind(self.profile,self.registry,self.exe)

    def test_unknown_game_build_rejected(self):
        self.profile["game_sha256"]="a"*64
        with self.assertRaisesRegex(ValueError,"EXACT_GAME_EXECUTABLE_SHA256_MISMATCH"):
            bind(self.profile,self.registry,self.exe)

    def test_x86_32bit_requires_other_backend(self):
        self.exe.write_bytes(pe(machine=0x14c,magic=0x10b))
        self.profile["game_sha256"]=hashlib.sha256(self.exe.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,"WINDOWS_X86_64_PE32_PLUS_REQUIRED"):
            bind(self.profile,self.registry,self.exe)

    def test_ps4_self_is_not_misrouted_into_wine(self):
        self.exe.write_bytes(bytes.fromhex("4f153d1d")+bytes(508))
        self.profile["game_sha256"]=hashlib.sha256(self.exe.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,"NOT_PE_DOS_HEADER"):
            bind(self.profile,self.registry,self.exe)

    def test_symlink_is_not_traversed(self):
        link=self.root/"link.exe"
        link.symlink_to(self.exe)
        with self.assertRaisesRegex(ValueError,"SYMLINK_GAME_EXECUTABLE_DENIED"):
            bind(self.profile,self.registry,link)

    def test_profile_cannot_be_enabled_by_hash(self):
        self.profile["enabled"]=True
        with self.assertRaisesRegex(ValueError,"UNQUALIFIED_PROFILE_MUST_REMAIN_DISABLED"):
            bind(self.profile,self.registry,self.exe)


if __name__ == "__main__":
    unittest.main()
