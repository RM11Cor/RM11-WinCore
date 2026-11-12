#!/usr/bin/env python3
"""Only original synthetic fixtures: never original proprietary CarX binaries."""
from __future__ import annotations
import importlib.util
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "carx_authorized_gate",root/"tools/carx_native_android_artifact_gate.py")
gate=importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(gate)

def synthetic_arm64_elf(machine=183,kind=3):
    b=bytearray(64)
    b[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI",b,16,kind,machine,1)
    return bytes(b)

def make_apk(path:Path,libs=None,assets=True,extra=None):
    if libs is None:
        libs={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS}
    with zipfile.ZipFile(path,"w") as z:
        z.writestr("AndroidManifest.xml",b"synthetic manifest; not an installable app")
        for k,v in libs.items():
            z.writestr(k,v)
        if assets:
            z.writestr("assets/bin/Data/globalgamemanagers",b"synthetic Unity data")
        if extra:
            for k,v in extra.items():
                z.writestr(k,v)
    return path

class NativePortGate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def project(self):
        (self.root/"ProjectSettings").mkdir(exist_ok=True)
        (self.root/"ProjectSettings/ProjectVersion.txt").write_text(
            "m_EditorVersion: 6000.3.8f1\n",encoding="utf-8")
        gameplay=self.root/"Assets/CarXStreetNativePort/Gameplay"
        scenes=self.root/"Assets/CarXStreetNativePort/Scenes"
        gameplay.mkdir(parents=True)
        scenes.mkdir(parents=True)
        (gameplay/"OriginalAuthorizedGameplay.cs").write_text("class OriginalAuthorizedGameplay {}\n")
        (scenes/"Test.unity").write_text("synthetic scene")
        return self.root

    def test_reject_original_extracted_pc_game_not_unity_project(self):
        (self.root/"GameAssembly.dll").write_bytes(b"MZ"+bytes(64))
        with self.assertRaises(gate.GateError):
            gate.inspect("project",self.root)

    def test_right_version_and_structure_but_no_game_authentication(self):
        r=gate.inspect("project",self.project())
        self.assertTrue(r["correct_source_project_structure_for_export"])
        self.assertFalse(r["actual_carx_gameplay_source_identity_proven"])
        self.assertFalse(r["ownership_or_permission_proven_by_file_scan"])
        self.assertFalse(r["original_carx_pc_android_port_proven"])

    def test_wrong_unity_editor_version_rejected(self):
        self.project()
        (self.root/"ProjectSettings/ProjectVersion.txt").write_text(
            "m_EditorVersion: 2022.3.62f1\n")
        with self.assertRaises(gate.GateError):
            gate.inspect("project",self.root)

    def test_no_gameplay_scripts_rejected(self):
        self.project()
        (self.root/"Assets/CarXStreetNativePort/Gameplay/OriginalAuthorizedGameplay.cs").unlink()
        with self.assertRaises(gate.GateError):
            gate.inspect("project",self.root)

    def test_no_unity_game_scenes_rejected(self):
        self.project()
        (self.root/"Assets/CarXStreetNativePort/Scenes/Test.unity").unlink()
        with self.assertRaises(gate.GateError):
            gate.inspect("project",self.root)

    def test_refuse_copy_of_windows_bundles_as_android_assets(self):
        self.project()
        (self.root/"Assets/StreamingAssets/aa/StandaloneWindows64").mkdir(parents=True)
        with self.assertRaises(gate.GateError):
            gate.inspect("project",self.root)

    def test_valid_arm64_three_unity_lib_headers_still_not_game_proof(self):
        path=make_apk(self.root/"candidate.apk")
        r=gate.inspect("apk",path)
        self.assertEqual(len(r["arm64_unity_native_libraries"]),3)
        self.assertTrue(r["android_arm64_unity_libraries_header_verified"])
        self.assertFalse(r["original_carx_pc_android_port_proven"])
        self.assertFalse(r["gameplay_code_identity_verified"])
        self.assertFalse(r["android_signed_certificate_verified"])

    def test_one_wrong_x86_library_rejected(self):
        libs={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS}
        libs["lib/arm64-v8a/libil2cpp.so"]=synthetic_arm64_elf(machine=62)
        path=make_apk(self.root/"candidate.apk",libs=libs)
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",path)

    def test_windows_gameassembly_dll_masquerading_as_android_so_rejected(self):
        libs={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS}
        libs["lib/arm64-v8a/libil2cpp.so"]=b"MZ"+bytes(62)
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",libs=libs))

    def test_no_il2cpp_lib_is_not_native_game(self):
        libs={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS
              if not name.endswith("/libil2cpp.so")}
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",libs=libs))

    def test_no_runtime_data_is_not_unity_player(self):
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",assets=False))

    def test_pc_game_binary_copied_in_zip_refused(self):
        for name in ("assets/PC/GameAssembly.dll","assets/PC/CarX Street.exe"):
            with self.subTest(name=name):
                with self.assertRaises(gate.GateError):
                    gate.inspect("apk",make_apk(self.root/"candidate.apk",
                        extra={name:b"MZ"+bytes(64)}))

    def test_zip_path_traversal_refused(self):
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",
                extra={"../asset.bin":b"bad"}))

    def test_duplicate_zip_native_library_refused(self):
        path=self.root/"dupe.apk"
        with zipfile.ZipFile(path,"w") as z:
            z.writestr("AndroidManifest.xml",b"manifest")
            for name in gate.NATIVE_LIBS:
                z.writestr(name,synthetic_arm64_elf())
            z.writestr("lib/arm64-v8a/libunity.so",synthetic_arm64_elf())
            z.writestr("assets/bin/Data/globalgamemanagers",b"synthetic")
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",path)

    def test_truncated_elf_rejected(self):
        bad={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS}
        bad["lib/arm64-v8a/libunity.so"]=b"\x7fELF"+bytes(23)
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",libs=bad))

    def test_wrong_elf_type_rejected(self):
        libs={name:synthetic_arm64_elf() for name in gate.NATIVE_LIBS}
        libs["lib/arm64-v8a/libmain.so"]=synthetic_arm64_elf(kind=2)
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",make_apk(self.root/"candidate.apk",libs=libs))

    def test_not_a_zip_rejected(self):
        (self.root/"fake.apk").write_bytes(b"NOT AN APK")
        with self.assertRaises(zipfile.BadZipFile):
            gate.inspect("apk",self.root/"fake.apk")

    def test_symlink_apk_rejected(self):
        p=make_apk(self.root/"real.apk")
        symlink=self.root/"notreal.apk"
        symlink.symlink_to(p)
        with self.assertRaises(gate.GateError):
            gate.inspect("apk",symlink)

if __name__=="__main__":
    unittest.main(verbosity=2)
