#!/usr/bin/env python3
"""No original copyrighted game data; only synthetic safe PE/catalog fixtures.

Test standalone Windows dependency and Addressables platform evidence, while
never accepting a native Android gameplay/asset compatibility claim.
"""
from __future__ import annotations
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "gate",root/"tools/carx_windows_gamecode_port_gate.py")
gate=importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(gate)

def synth_pe(dll="KERNEL32.dll", machine=0x8664, pe32plus=True,
             import_terminator=True) -> bytes:
    raw=bytearray(2048)
    raw[0:2]=b"MZ"
    struct.pack_into("<I",raw,0x3c,0x80)
    raw[0x80:0x84]=b"PE\0\0"
    struct.pack_into("<HHIIIHH",raw,0x84,machine,1,0,0,0,
                     0xF0 if pe32plus else 0xE0,0x2002)
    opt=0x98
    struct.pack_into("<H",raw,opt,0x20b if pe32plus else 0x10b)
    directory_offset=112 if pe32plus else 96
    struct.pack_into("<II",raw,opt+directory_offset+8,0x2000,40)
    sec=opt+(0xF0 if pe32plus else 0xE0)
    raw[sec:sec+8]=b".idata\0\0"
    struct.pack_into("<4I",raw,sec+8,0x400,0x2000,0x400,0x400)
    struct.pack_into("<5I",raw,0x400,0x2100,0,0,0x2050,0x2100)
    if not import_terminator:
        struct.pack_into("<5I",raw,0x414,0x2100,0,0,0x2050,0x2100)
    name=dll.encode("ascii")+b"\0"
    raw[0x450:0x450+len(name)]=name
    return bytes(raw)

class TestWindowsPortGate(unittest.TestCase):
    def setUp(self):
        x=tempfile.TemporaryDirectory()
        self.addCleanup(x.cleanup)
        self.root=Path(x.name)

    def write(self,name,content):
        p=self.root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        if isinstance(content,str):
            p.write_text(content,encoding="utf-8")
        else:
            p.write_bytes(content)
        return p

    def test_x64_original_pe_imports_real_win32_dll(self):
        d=gate.inspect_pe(self.write("GameAssembly.dll",synth_pe()))
        self.assertTrue(d["pe_valid"])
        self.assertEqual(d["architecture"],"x86_64")
        self.assertEqual(d["import_dll_names"],["kernel32.dll"])
        self.assertEqual(d["windows_system_imports"],["kernel32.dll"])
        self.assertFalse(d["android_elf_bionic_binary"])

    def test_arm64_pe_also_not_android_elf(self):
        d=gate.inspect_pe(self.write("GameAssembly.dll",synth_pe(machine=0xaa64)))
        self.assertEqual(d["architecture"],"ARM64")
        self.assertFalse(d["android_elf_bionic_binary"])

    def test_x86_32_pe_does_not_convert_to_android(self):
        d=gate.inspect_pe(self.write("GameAssembly.dll",synth_pe(machine=0x14c,pe32plus=False)))
        self.assertEqual(d["architecture"],"x86_32")
        self.assertFalse(d["android_game_code_execution_proven"])

    def test_steam_api_is_classified_without_execution(self):
        d=gate.inspect_pe(self.write("GameAssembly.dll",synth_pe("steam_api64.dll")))
        self.assertEqual(d["steam_related_imports"],["steam_api64.dll"])
        self.assertFalse(d["android_game_code_execution_proven"])

    def test_eac_names_only_not_runtime_proof(self):
        d=gate.inspect_pe(self.write("GameAssembly.dll",synth_pe("EasyAntiCheat_EOS.dll")))
        self.assertTrue(d["anti_cheat_related_imports"])
        self.assertTrue(d["eos_related_imports"])
        self.assertFalse(d["native_android_game_code_recompilation_inputs_proven"])

    def test_missing_unmodified_dll_is_no_native_proof(self):
        d=gate.inspect_game(self.root)
        self.assertFalse(d["game_code_inputs"]["game_il2cpp"]["present"])
        self.assertFalse(d["android_arm64_game_logic_available"])
        self.assertFalse(d["native_pc_to_android_port_proven"])

    def test_owned_game_imports_and_catalog_census(self):
        self.write("GameAssembly.dll",synth_pe("d3d11.dll"))
        self.write("UnityPlayer.dll",synth_pe("kernel32.dll"))
        catalog={
            "m_InternalIds":["{UnityEngine.AddressableAssets.Addressables.RuntimePath}/aa/StandaloneWindows64/car.bundle",
                             "file:///game/aa/StandaloneWindows64/shader.bundle",
                             "{UnityEngine.AddressableAssets.Addressables.RuntimePath}/aa/Android/test.bundle"],
            "m_ProviderIds":["BundledAssetProvider"]
        }
        self.write("CarX Street_Data/StreamingAssets/aa/catalog.json",json.dumps(catalog))
        report=gate.inspect_game(self.root)
        self.assertTrue(report["game_code_inputs"]["game_il2cpp"]["pe_valid"])
        self.assertEqual(report["assets"]["internal_id_count"],3)
        self.assertEqual(report["assets"]["windows64_reference_count"],2)
        self.assertEqual(report["assets"]["android_named_reference_count"],1)
        self.assertEqual(report["assets"]["bundle_extension_reference_count"],3)
        self.assertEqual(report["assets"]["shader_named_reference_count"],1)
        self.assertFalse(report["android_assetbundle_targets_proven"])
        self.assertFalse(report["native_pc_to_android_port_proven"])
        self.assertFalse(report["original_game_first_frame_proven"])

    def test_truncated_pe_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(self.write("GameAssembly.dll",b"MZ"+bytes(90)))

    def test_fake_elf_and_macho_must_not_be_pe(self):
        for i,blob in enumerate((b"\x7fELF",b"\xcf\xfa\xed\xfe")):
            with self.subTest(blob=blob):
                with self.assertRaises(gate.FormatError):
                    gate.inspect_pe(self.write("GameAssembly.dll",blob+bytes(500)))

    def test_missing_pe_signature_rejected(self):
        bad=bytearray(synth_pe())
        bad[0x80:0x84]=b"FAKE"
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(self.write("GameAssembly.dll",bad))

    def test_import_section_outside_file_rejected(self):
        bad=bytearray(synth_pe())
        struct.pack_into("<I",bad,0x188+20,7000)
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(self.write("GameAssembly.dll",bad))

    def test_unterminated_pe_import_directory_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(self.write("GameAssembly.dll",synth_pe(import_terminator=False)))

    def test_bad_import_name_rva_rejected(self):
        bad=bytearray(synth_pe())
        struct.pack_into("<I",bad,0x400+12,0x6000)
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(self.write("GameAssembly.dll",bad))

    def test_catalog_bad_shape_rejected(self):
        p=self.write("catalog.json",'{"m_InternalIds":{"fake":"a.bundle"}}')
        with self.assertRaises(gate.FormatError):
            gate.inspect_catalog(p)

    def test_catalog_missing_ids_rejected(self):
        with self.assertRaises(gate.FormatError):
            gate.inspect_catalog(self.write("catalog.json",'{"x":1}'))

    def test_catalog_huge_id_rejected(self):
        p=self.write("catalog.json",json.dumps({"m_InternalIds":["a"*9000]}))
        with self.assertRaises(gate.FormatError):
            gate.inspect_catalog(p)

    def test_catalog_windows_no_android_remains_blocked(self):
        p=self.write("catalog.json",json.dumps({
            "m_InternalIds":["aa/StandaloneWindows64/car.bundle"]
        }))
        d=gate.inspect_catalog(p)
        self.assertEqual(d["android_named_reference_count"],0)
        self.assertFalse(d["windows_bundles_to_android_converted"])

    def test_symlink_dll_not_opened(self):
        p=self.write("src.dll",synth_pe())
        dst=self.root/"GameAssembly.dll"
        dst.symlink_to(p)
        with self.assertRaises(gate.FormatError):
            gate.inspect_pe(dst)

if __name__=="__main__":
    unittest.main(verbosity=2)
