"""KERNIX component staging-tree validator tests; no real runtime claimed."""
import copy
import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from kernix_component_payload_gate import verify_tree


def pe(machine=0x8664):
    blob=bytearray(256)
    blob[0:2]=b"MZ"
    struct.pack_into("<I",blob,60,64)
    blob[64:68]=b"PE\0\0"
    struct.pack_into("<H",blob,68,machine)
    return bytes(blob)


def fixture(root):
    root=Path(root)
    (root/"bin").mkdir()
    (root/"licenses").mkdir()
    (root/"bin"/"dxgi.dll").write_bytes(pe())
    (root/"licenses"/"COPYING").write_bytes(b"test-license-notice\n")
    entries=[]
    for name, fmt, machine in (
        ("bin/dxgi.dll","pe","x86_64"),
        ("licenses/COPYING","data","none"),
    ):
        b=(root/name).read_bytes()
        entries.append({"path":name,"size_bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),
                        "format":fmt,"machine":machine})
    return {"schema":"kernix.component-payload.v1",
            "component":{"id":"dxvk-test","kind":"dxvk","version":"0-test"},
            "source":{"repository":"doitsujin/dxvk","git_commit":"a"*40,"license_spdx":"Zlib"},
            "files":entries, "license_paths":["licenses/COPYING"]}


class GateTests(unittest.TestCase):
    def test_valid_staged_pe_and_notice_is_not_installed(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d)
            result=verify_tree(d,m)
            self.assertTrue(result["all_files_hashed"])
            self.assertFalse(result["installed"])
            self.assertFalse(result["runtime_tested"])

    def test_pe_machine_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);m["files"][0]["machine"]="arm64"
            with self.assertRaisesRegex(ValueError,"PE_MACHINE_MISMATCH"):
                verify_tree(d,m)

    def test_bad_digest(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);m["files"][0]["sha256"]="0"*64
            with self.assertRaisesRegex(ValueError,"PE_SHA256_MISMATCH"):
                verify_tree(d,m)

    def test_extra_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);(Path(d)/"surprise.txt").write_text("not in manifest")
            with self.assertRaisesRegex(ValueError,"EXTRA_OR_MISSING_FILES"):
                verify_tree(d,m)

    def test_missing_license(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);m["license_paths"]=[]
            with self.assertRaisesRegex(ValueError,"INVALID_LICENSE_FILES"):
                verify_tree(d,m)

    def test_symlink_and_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d)
            (Path(d)/"bin"/"link").symlink_to("dxgi.dll")
            with self.assertRaisesRegex(ValueError,"SYMLINK_NOT_ALLOWED"):
                verify_tree(d,m)
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d)
            os.link(Path(d)/"bin"/"dxgi.dll",Path(d)/"bin"/"hardlink")
            with self.assertRaisesRegex(ValueError,"NONREGULAR_OR_LINKED_FILE"):
                verify_tree(d,m)

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);m["files"][0]["path"]="../dxgi.dll"
            with self.assertRaisesRegex(ValueError,"UNSAFE_BUNDLE_PATH"):
                verify_tree(d,m)

    def test_bad_source_revision_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m=fixture(d);m["source"]["git_commit"]="main"
            with self.assertRaisesRegex(ValueError,"SOURCE_NOT_PINNED"):
                verify_tree(d,m)


if __name__=="__main__":
    unittest.main()
