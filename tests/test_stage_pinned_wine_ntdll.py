import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage_pinned_wine_ntdll import stage, NTDLL_MEMBER, NTDLL_DEST, check_elf


def fake_elf():
    data=bytearray(b"\0"*110000)
    data[:6]=b"\x7fELF\x02\x01"
    data[16:20]=b"\x03\x00\xb7\x00"
    return bytes(data)


class PinnedNativeNtdllTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)
        self.zip=root/"pinned-wine.zip"
        self.report=root/"legacy.json"
        self.output=root/"lib"
        self.data=fake_elf()
        self.write_zip(self.data)
        self.update_manifest()

    def tearDown(self):
        self.tmp.cleanup()

    def write_zip(self,data,duplicate=False):
        with zipfile.ZipFile(self.zip,"w") as z:
            z.writestr(NTDLL_MEMBER,data)
            if duplicate:
                z.writestr(NTDLL_MEMBER,data)

    def update_manifest(self):
        report={
            "schema":"rm11.engine.pinned-legacy-runtime-stage.v1",
            "baseline_apk_sha256":
                "1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8",
            "pinned_runtime_components":{
                "assets/runtime/rm11-wine-stack.zip":{
                    "sha256":hashlib.sha256(self.zip.read_bytes()).hexdigest(),
                    "size_bytes":self.zip.stat().st_size
                }
            }
        }
        self.report.write_text(json.dumps(report))

    def test_exact_bytes_no_prefix_write(self):
        result=stage(self.zip,self.report,self.output)
        self.assertEqual((self.output/NTDLL_DEST).read_bytes(),self.data)
        self.assertEqual(result["sha256"],hashlib.sha256(self.data).hexdigest())
        self.assertFalse(result["wine_prefix_mutated"])
        self.assertFalse(result["engine_activation"])

    def test_fail_before_write_if_digest_invalid(self):
        self.zip.write_bytes(self.zip.read_bytes()+b"TAMPERED")
        with self.assertRaisesRegex(ValueError,"IDENTITY_MISMATCH"):
            stage(self.zip,self.report,self.output)
        self.assertFalse((self.output/NTDLL_DEST).exists())

    def test_fail_on_elf_wrong_architecture(self):
        self.write_zip(b"MZ"+self.data[2:])
        self.update_manifest()
        with self.assertRaisesRegex(ValueError,"NOT_AARCH64_ET_DYN"):
            stage(self.zip,self.report,self.output)

    def test_fail_on_duplicate_ntdll_member(self):
        self.write_zip(self.data,duplicate=True)
        self.update_manifest()
        with self.assertRaisesRegex(ValueError,"MISSING_OR_DUPLICATED"):
            stage(self.zip,self.report,self.output)

    def test_never_overwrite_existing_signed_library(self):
        self.output.mkdir()
        (self.output/NTDLL_DEST).write_bytes(b"PROTECTED")
        with self.assertRaisesRegex(ValueError,"ALREADY_EXISTS"):
            stage(self.zip,self.report,self.output)
        self.assertEqual((self.output/NTDLL_DEST).read_bytes(),b"PROTECTED")

    def test_fail_on_untrusted_manifest_identity(self):
        doc=json.loads(self.report.read_text())
        doc["baseline_apk_sha256"]="0"*64
        self.report.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,"IDENTITY_MISMATCH"):
            stage(self.zip,self.report,self.output)


if __name__ == "__main__":
    unittest.main()
