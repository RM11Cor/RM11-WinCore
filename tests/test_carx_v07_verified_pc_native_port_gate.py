#!/usr/bin/env python3
"""Adversarial synthetic tests, never a substitute for original CarX game code."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "carx_v07_gates",ROOT/"tools/carx_v07_verified_pc_native_port_gate.py")
gate=importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(gate)

def original_header_fixture():
    def source(imports):
        return {
            "present":True,
            "pe_header_valid":True,
            "machine_architecture":"Windows-PE-x86_64",
            "source_binary_format":"PE32+",
            "pe_import_directory_complete":True,
            "saf_random_read_supported":True,
            "static_import_library_names":imports,
        }
    return {
        "schema":"rm11carx.pc-port-readonly-inspector.v1",
        "inspector_version":"0.7.0",
        "source_game":"CarX Street PC (Unity IL2CPP)",
        "read_only":True,
        "game_files_transmitted":False,
        "counts":{"files":906,"scan_incomplete":False},
        "windows_source_dependency_probe":{
            "schema":"rm11carx.android-saf-windows-gamecode-asset-gate.v1",
            "executes_windows_game_binaries":False,
            "android_arm64_carx_game_logic_proven":False,
            "pc_executable_dependencies":{
                "game_assembly":source(["baselib.dll","kernel32.dll"]),
                "unity_player":source(["kernel32.dll","d3d11.dll","dxgi.dll","opengl32.dll"])
            },
            "addressables_platform_references":{
                "present":True,
                "full_file_parsed":True,
                "internal_id_count":54490,
                "standalone_windows64_references":807,
                "bundle_extension_references":807,
                "android_named_references":1,
                "android_target_bundle_shaders_compatible_proven":False,
                "original_pc_windows_bundle_conversion_proven":False,
            },
        },
        "unity_deep_probe":{
            "windows64_bundle_count":808,
            "unity_serialized_file_headers":{
                "candidate_unity_editor_versions":["6000.3.8f1"],
            },
        },
        "native_arm64_vulkan_preflight":{
            "native_gpu_work_verified":True,
        },
        "device":{
            "model":"FAKE_UNIQUE_USER_DEVICE_STRING_NEVER_PRINT_THIS",
            "serial":"SECRET_EXCLUDE_FROM_PUBLIC_SUMMARY",
        }
    }

class Gate(unittest.TestCase):
    def setUp(self):
        self.input=original_header_fixture()

    def rejects(self):
        with self.assertRaises(gate.ValidationError):
            gate.evaluate(self.input)

    def test_real_807_vs_808_discrepancy_is_not_missing_file_proof(self):
        d=gate.evaluate(self.input)
        self.assertEqual(d["addressables"]["bundle_file_minus_catalog_reference_count"],1)
        self.assertFalse(d["addressables"]["bundle_file_count_vs_catalog_count_is_missing_file_proof"])
        self.assertFalse(d["addressables"]["catalog_dependency_closure_verified"])

    def test_android_substring_does_not_prove_android_bundle(self):
        d=gate.evaluate(self.input)
        self.assertEqual(d["addressables"]["catalog_android_name_substring_count"],1)
        self.assertFalse(d["addressables"]["android_substring_is_android_asset_bundle_proof"])
        self.assertFalse(d["addressables"]["android_target_game_bundle_verified"])

    def test_vulkan_real_hardware_is_not_game_runtime(self):
        d=gate.evaluate(self.input)
        self.assertTrue(d["hardware"]["original_independent_native_arm64_gpu_clear_and_readback_proven"])
        self.assertFalse(d["hardware"]["gpu_success_means_original_game_runnable"])
        self.assertFalse(d["native_port_acceptance"]["strict_no_emulation_playable_pc_port"])

    def test_actual_win32_game_and_d3d_unity_imports_classified(self):
        d=gate.evaluate(self.input)
        self.assertTrue(d["source_code"]["game_assembly"]["unity_baselib_dependency_detected"])
        self.assertEqual(d["source_code"]["unity_player"]["windows_graphics_dlls_present"],
                         ["d3d11.dll","dxgi.dll","opengl32.dll"])

    def test_zero_static_steam_eac_is_not_zero_dynamic_dependencies(self):
        d=gate.evaluate(self.input)
        self.assertEqual(d["source_code"]["game_assembly"]["steam_eac_eos_static_imports_present"],[])
        self.assertTrue(d["source_code"]["game_assembly"]["static_import_absence_does_not_exclude_runtime_dynamic_loads"])

    def test_user_device_identity_and_original_paths_excluded(self):
        result=str(gate.evaluate(self.input))
        self.assertNotIn("FAKE_UNIQUE_USER_DEVICE_STRING_NEVER_PRINT_THIS",result)
        self.assertNotIn("SECRET_EXCLUDE_FROM_PUBLIC_SUMMARY",result)
        self.assertNotIn("/sdcard/",result)

    def test_no_gameplay_and_no_reconstructed_android_logic(self):
        d=gate.evaluate(self.input)
        for key in ("G0_authorized_original_android_arm64_gameplay_code_verified",
                    "G1_original_android_platform_asset_bundle_verified",
                    "G2_original_carx_game_scene_frame_and_controls_verified"):
            self.assertFalse(d["native_port_acceptance"][key])

    def test_bad_schema_fails_closed(self):
        self.input["schema"]="fake inspector"
        self.rejects()

    def test_old_inspector_version_fails_closed(self):
        self.input["inspector_version"]="0.6.0"
        self.rejects()

    def test_wrong_game_fails_closed(self):
        self.input["source_game"]="Unrelated Game"
        self.rejects()

    def test_incomplete_source_listing_fails_closed(self):
        self.input["counts"]["scan_incomplete"]=True
        self.rejects()

    def test_pe_random_read_failure_fails_closed(self):
        self.input["windows_source_dependency_probe"]["pc_executable_dependencies"]["game_assembly"]["saf_random_read_supported"]=False
        self.rejects()

    def test_pe_import_error_fails_closed(self):
        self.input["windows_source_dependency_probe"]["pc_executable_dependencies"]["unity_player"]["pe_import_directory_complete"]=False
        self.rejects()

    def test_missing_catalog_fails_closed(self):
        self.input["windows_source_dependency_probe"]["addressables_platform_references"]["full_file_parsed"]=False
        self.rejects()

    def test_cannot_forge_native_code_claim(self):
        self.input["windows_source_dependency_probe"]["android_arm64_carx_game_logic_proven"]=True
        self.rejects()

    def test_missing_pe_binary_fails_closed(self):
        self.input["windows_source_dependency_probe"]["pc_executable_dependencies"]["unity_player"]["present"]=False
        self.rejects()

    def test_unrecognized_game_cpu_architecture_fails_closed(self):
        self.input["windows_source_dependency_probe"]["pc_executable_dependencies"]["game_assembly"]["machine_architecture"]="unknown"
        self.rejects()

    def test_negative_asset_delta_not_a_missing_file_by_itself(self):
        self.input["unity_deep_probe"]["windows64_bundle_count"]=805
        d=gate.evaluate(self.input)
        self.assertEqual(d["addressables"]["bundle_file_minus_catalog_reference_count"],-2)
        self.assertFalse(d["addressables"]["bundle_file_count_vs_catalog_count_is_missing_file_proof"])

    def test_invalid_numeric_counts_fails_closed(self):
        self.input["windows_source_dependency_probe"]["addressables_platform_references"]["internal_id_count"]=True
        self.rejects()

if __name__=="__main__":
    unittest.main(verbosity=2)
