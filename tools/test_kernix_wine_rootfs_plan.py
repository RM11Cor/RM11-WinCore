"""Synthetic rootfs contract tests; no real Wine, FEX or Android execution."""
import copy
import unittest
from kernix_wine_rootfs_plan import compile_contract, COMMIT


def fixture():
    return {
        "schema": "kernix.wine-linux-x64-elf-dependencies.v1",
        "source": "wine-mirror/wine", "upstream_commit": COMMIT,
        "host": "ubuntu-24.04-x86_64-glibc", "sha256_verified": True,
        "elf_files_audited": 1, "needed_sonames": ["libc.so.6", "ntdll.so"],
        "not_named_in_staged_files": ["libc.so.6"],
        "interpreters": ["/lib64/ld-linux-x86-64.so.2"],
        "files": [{"path": "opt/kernix-wine-linux-x64/bin/wine",
                   "sha256": "a" * 64, "needed": ["libc.so.6", "ntdll.so"],
                   "interpreter": "/lib64/ld-linux-x86-64.so.2",
                   "dynamic_search_paths": {}}],
        "rootfs_dependency_resolution_tested": False, "fex_arm64_tested": False,
        "android_bionic_compatible": False, "windows_game_tested": False,
    }


class RootfsContractTests(unittest.TestCase):
    def test_contract_keeps_unverified_boundaries(self):
        result = compile_contract(fixture())
        self.assertEqual(result["external_guest_soname_candidates"], ["libc.so.6"])
        self.assertEqual(result["staged_soname_name_candidates"], ["ntdll.so"])
        self.assertEqual(result["required_guest_interpreters"], ["/lib64/ld-linux-x86-64.so.2"])
        self.assertFalse(result["guest_rootfs_resolved"])
        self.assertFalse(result["android_bionic_compatible"])
        self.assertTrue(result["upstream_wine_license_must_be_preserved"])

    def test_stable_hash_and_changed_report(self):
        self.assertEqual(compile_contract(fixture()), compile_contract(fixture()))
        data = fixture()
        data["files"][0]["sha256"] = "b" * 64
        self.assertNotEqual(compile_contract(data)["dependency_report_sha256"],
                            compile_contract(fixture())["dependency_report_sha256"])

    def test_false_compatibility_claim_rejected(self):
        for key in ("rootfs_dependency_resolution_tested", "fex_arm64_tested",
                    "android_bionic_compatible", "windows_game_tested"):
            data = fixture()
            data[key] = True
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "UNPROVEN_RUNTIME_CLAIM"):
                compile_contract(data)

    def test_unpinned_or_unverified_source_rejected(self):
        for key, value in (("upstream_commit", "a" * 40), ("sha256_verified", False)):
            data = fixture()
            data[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "UNVERIFIED_PROVENANCE"):
                compile_contract(data)

    def test_path_traversal_and_duplicate_rejected(self):
        data = fixture()
        data["files"][0]["path"] = "opt/kernix-wine-linux-x64/../escape"
        with self.assertRaisesRegex(ValueError, "INVALID_ELF_RECORD"):
            compile_contract(data)
        data = fixture()
        data["files"].append(copy.deepcopy(data["files"][0]))
        data["elf_files_audited"] = 2
        with self.assertRaisesRegex(ValueError, "INVALID_ELF_RECORD"):
            compile_contract(data)

    def test_mismatched_sonames_and_loader_rejected(self):
        for key, value in (("needed_sonames", []),
                           ("not_named_in_staged_files", ["unknown.so"]),
                           ("interpreters", [])):
            data = fixture()
            data[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "INCONSISTENT_DEPENDENCIES"):
                compile_contract(data)

    def test_unsafe_loader_or_search_path_rejected(self):
        data = fixture()
        data["files"][0]["interpreter"] = "/lib64/../tmp/ld.so"
        with self.assertRaisesRegex(ValueError, "INVALID_INTERPRETER"):
            compile_contract(data)
        data = fixture()
        data["files"][0]["dynamic_search_paths"] = {"UNSAFE": "/tmp"}
        with self.assertRaisesRegex(ValueError, "INVALID_SEARCH_PATH"):
            compile_contract(data)

    def test_preserves_dynamic_loader_search_path_evidence(self):
        data = fixture()
        data["files"][0]["dynamic_search_paths"] = {"RUNPATH": "$ORIGIN/../lib"}
        contract = compile_contract(data)
        self.assertEqual(contract["elf_dynamic_search_path_evidence"], [
            {"path": "opt/kernix-wine-linux-x64/bin/wine",
             "dynamic_search_paths": {"RUNPATH": "$ORIGIN/../lib"}}])
        self.assertFalse(contract["guest_rootfs_resolved"])
        self.assertEqual(compile_contract(fixture())["elf_dynamic_search_path_evidence"], [])
        self.assertNotEqual(contract["dependency_report_sha256"],
                            compile_contract(fixture())["dependency_report_sha256"])

    def test_malformed_external_soname_entries_rejected(self):
        for bad in ([None], ["libc.so.6", {}], ["libc.so.6", "libc.so.6"]):
            data = fixture()
            data["not_named_in_staged_files"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "INCONSISTENT_DEPENDENCIES"):
                compile_contract(data)

    def test_invalid_sha256_rejected(self):
        data = fixture()
        data["files"][0]["sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "INVALID_ELF_RECORD"):
            compile_contract(data)


if __name__ == "__main__":
    unittest.main()
