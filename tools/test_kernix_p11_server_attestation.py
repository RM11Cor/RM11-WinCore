#!/usr/bin/env python3
"""Fast signed-ELF gate acceptance tests; no Android/NDK required."""
import importlib.util
import hashlib
import pathlib
import struct
import tempfile
import unittest

PATH=pathlib.Path(__file__).resolve().parent/"build_kernix_proton_fex_bundle.py"
spec=importlib.util.spec_from_file_location("kernix_p11_bundle",PATH)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ServerGateTests(unittest.TestCase):
    def fixture(self,root):
        root=pathlib.Path(root)
        binary=root/"kernix-verified-server"/"wineserver"
        binary.parent.mkdir(parents=True)
        # Synthetic AArch64 ELF plus source-compiled guard markers; this
        # checks rejection logic, not the credibility of a real binary build.
        blob=bytearray(80000)
        blob[:6]=b"\\x7fELF\\x02\\x01"
        struct.pack_into("<H",blob,18,183)
        tail=b"\\x00".join(mod.SERVER_MARKERS)
        blob[-len(tail):]=tail
        binary.write_bytes(blob)
        (root/"KERNIX-SERVER-BUILD-PROOF.txt").write_text(
            "\\n".join([
                "UPSTREAM_REV="+mod.PINNED_SERVER_UPSTREAM,
                "SOURCE_PATCHED=YES",
                "BINARY_COMPILED=YES",
                "APPLIED_TO_KERNIX_APK=NO",
                "DEVICE_GUI_QUALIFIED=NO"])+"\\n")
        (root/"KERNIX-SERVER-SHA256.txt").write_text(
            hashlib.sha256(blob).hexdigest()+"  /runner/native/bin/wineserver\\n")
        return binary

    def test_valid_pinned_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            binary=self.fixture(root)
            out,sha=mod.verify_server_artifact(pathlib.Path(root))
            self.assertEqual(binary,out)
            self.assertEqual(sha,hashlib.sha256(binary.read_bytes()).hexdigest())

    def test_tampered_binary_sha_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            binary=self.fixture(root)
            b=bytearray(binary.read_bytes())
            b[100]=0x80
            binary.write_bytes(b)
            with self.assertRaisesRegex(ValueError,"SHA256_MISMATCH"):
                mod.verify_server_artifact(pathlib.Path(root))

    def test_wrong_architecture_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            binary=self.fixture(root)
            b=bytearray(binary.read_bytes())
            struct.pack_into("<H",b,18,62)
            binary.write_bytes(b)
            with self.assertRaisesRegex(ValueError,"WRONG_ABI"):
                mod.verify_server_artifact(pathlib.Path(root))

    def test_partial_source_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            self.fixture(root)
            proof=pathlib.Path(root)/"KERNIX-SERVER-BUILD-PROOF.txt"
            proof.write_text(proof.read_text().replace("SOURCE_PATCHED=YES","SOURCE_PATCHED=NO"))
            with self.assertRaisesRegex(ValueError,"SOURCE_PROOF_INVALID"):
                mod.verify_server_artifact(pathlib.Path(root))

    def test_missing_runtime_marker_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            binary=self.fixture(root)
            b=binary.read_bytes().replace(
                b"KERNIX_P11_QUEUE_NO_THREAD_DESKTOP",b"KERNIX_P11_QUEUE_UNSAFE_DISABLED")
            binary.write_bytes(b)
            with self.assertRaisesRegex(ValueError,"GUARD_NOT_COMPILED"):
                mod.verify_server_artifact(pathlib.Path(root))

if __name__=="__main__":
    unittest.main()
