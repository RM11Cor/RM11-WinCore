#!/usr/bin/env python3
"""Static graphics closure tests; never execute a Windows game or GPU."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from engine_graphics_provider_audit import inspect,pe_amd64,elf_aarch64


def digest(b):return hashlib.sha256(b).hexdigest()


def pe(machine=0x8664):
    b=bytearray(512);b[:2]=b"MZ";struct.pack_into("<I",b,0x3c,0x80)
    b[0x80:0x84]=b"PE\x00\x00"
    struct.pack_into("<H",b,0x84,machine)
    struct.pack_into("<H",b,0x98,0x20b)
    return bytes(b)


def elf(machine=183):
    b=bytearray(1024);b[:6]=b"\x7fELF\x02\x01"
    struct.pack_into("<HH",b,16,3,machine)
    return bytes(b)


class GraphicsContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.apk=Path(self.tmp.name)/"engine.apk"
        self.dll1=pe()
        self.dll2=pe()
        self.driver=elf()
        self.files={
            "assets/engine/providers/dxvk/x64/d3d11.dll":self.dll1,
            "assets/engine/providers/dxvk/x64/dxgi.dll":self.dll2,
            "lib/arm64-v8a/libvulkan_freedreno.so":self.driver,
        }
        self.data={
            "schema":"rm11.engine.bundle.v1",
            "dxvk":{
                "provider":"dxvk",
                "source_commit":"a"*40,
                "pe_files":{
                    k:{"apk_path":"assets/engine/providers/dxvk/x64/"+k,
                       "architecture":"x86_64","sha256":digest(self.files[
                       "assets/engine/providers/dxvk/x64/"+k])}
                    for k in ("d3d11.dll","dxgi.dll")
                }
            },
            "gpu":{
                "driver":"turnip","source_commit":"b"*40,
                "wsi":"hardware","architecture":"aarch64",
                "libc":"bionic",
                "apk_library":"lib/arm64-v8a/libvulkan_freedreno.so",
                "sha256":digest(self.driver),
            },
        }

    def tearDown(self):self.tmp.cleanup()

    def write(self,include_manifest=True):
        with zipfile.ZipFile(self.apk,"w") as z:
            for name,data in self.files.items():z.writestr(name,data)
            if include_manifest:z.writestr(
                "assets/engine/engine-bundle-manifest.json",json.dumps(self.data))

    def test_correct_binaries_still_do_not_certify_android_frames(self):
        self.write()
        result=inspect(self.apk)
        self.assertEqual(result["static_provider_gate"],
                         "PROVIDER_BINARIES_STRUCTURALLY_VERIFIED")
        self.assertFalse(result["release_eligible"])
        self.assertFalse(result["hardware_rendering_proven"])
        self.assertIn("WINDOW_PIXELS_REACHED_ANDROID_SURFACE",
                      result["unverified_runtime"])

    def test_manifest_alone_does_not_prove_provider(self):
        self.write(False)
        result=inspect(self.apk)
        self.assertEqual(result["static_provider_gate"],
                         "BLOCKED_NO_SIGNED_PROVIDER_MANIFEST")

    def test_windows_built_in_stubs_not_accepted_as_dxvk(self):
        self.files["assets/engine/providers/dxvk/x64/d3d11.dll"]=b"MZ"+b"bad"*180
        self.data["dxvk"]["pe_files"]["d3d11.dll"]["sha256"]=digest(
            self.files["assets/engine/providers/dxvk/x64/d3d11.dll"])
        self.write()
        result=inspect(self.apk)
        self.assertEqual(result["component_checks"]["dxvk_pe_d3d11"],
                         "BINARY_HASH_OR_PE_ARCH_INVALID")

    def test_x86_pe32_incorrect(self):
        self.files["assets/engine/providers/dxvk/x64/dxgi.dll"]=pe(0x14c)
        self.data["dxvk"]["pe_files"]["dxgi.dll"]["sha256"]=digest(
            self.files["assets/engine/providers/dxvk/x64/dxgi.dll"])
        self.write()
        self.assertEqual(inspect(self.apk)["component_checks"]["dxvk_pe_dxgi"],
                         "BINARY_HASH_OR_PE_ARCH_INVALID")

    def test_x86_64_linux_elf_not_turnip_for_android(self):
        self.files["lib/arm64-v8a/libvulkan_freedreno.so"]=elf(62)
        self.data["gpu"]["sha256"]=digest(self.files[
            "lib/arm64-v8a/libvulkan_freedreno.so"])
        self.write()
        result=inspect(self.apk)
        self.assertEqual(result["component_checks"]["turnip_android_native"],
                         "BINARY_HASH_OR_ELF_ARCH_INVALID")

    def test_manifest_must_match_actual_bytes(self):
        self.data["dxvk"]["pe_files"]["d3d11.dll"]["sha256"]="0"*64
        self.write()
        self.assertEqual(inspect(self.apk)["component_checks"]["dxvk_pe_d3d11"],
                         "BINARY_HASH_OR_PE_ARCH_INVALID")

    def test_native_lib_is_only_under_signed_apk_native_root(self):
        self.data["gpu"]["apk_library"]="assets/engine/libvulkan_freedreno.so"
        self.files["assets/engine/libvulkan_freedreno.so"]=self.files.pop(
            "lib/arm64-v8a/libvulkan_freedreno.so")
        self.write()
        self.assertEqual(inspect(self.apk)["component_checks"]["turnip_android_native"],
                         "TURNIP_METADATA_OR_NATIVE_PATH_INVALID")

    def test_manifest_wsi_claim_does_not_count_as_android_presentation(self):
        self.write()
        result=inspect(self.apk)
        self.assertEqual(result["declared_gpu_wsi"],"hardware")
        self.assertEqual(result["component_checks"]["turnip_hardware_wsi"],
                         "UNVERIFIED_ON_DEVICE")


if __name__=="__main__":
    unittest.main()
