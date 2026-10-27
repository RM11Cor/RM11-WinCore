#!/usr/bin/env python3
"""Host-only proofs for the APK-owned Wine process identity and release gate."""
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from build_engine_runtime_manifest import create,PINNED_BASELINE
from verify_engine_source_apk import audit

GAME_COMPONENTS={
    "lib/arm64-v8a/libwineprobe.so":b"\x7fELF_LOADER",
    "lib/arm64-v8a/libwineserverrm11.so":b"\x7fELF_WINESERVER",
    "assets/runtime/rm11-wine-stack.zip":b"FAKE_TEST_WINE_STACK",
}


def h(data):
    return hashlib.sha256(data).hexdigest()


class EngineRuntimeManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.native=self.root/"librm11_engine_supervisor.so"
        self.native.write_bytes(b"\x7fELF"+b"N"*6000)
        self.report=self.root/"pinned-source.json"
        self.manifest=self.root/"engine-native-manifest.json"
        self.apk=self.root/"debug.apk"
        self.report.write_text(json.dumps({
            "baseline_apk_sha256":PINNED_BASELINE,
            "pinned_runtime_components":{
                name:{"sha256":h(data),"size_bytes":len(data)}
                for name,data in GAME_COMPONENTS.items()
            }}))
        self.engine=create(self.report,self.native,self.manifest)

    def tearDown(self):
        self.tmp.cleanup()

    def fakeapk(self,mutate=None,alter_activation=False,missing_manifest=False):
        data=json.loads(self.manifest.read_text())
        if alter_activation:
            data["activation"]="READY_UNPROVEN"
        with zipfile.ZipFile(self.apk,"w") as z:
            z.writestr("AndroidManifest.xml",b"compiled-manifest")
            z.writestr("classes.dex",b"dex-dummy")
            z.writestr("lib/arm64-v8a/libXlorie.so",b"\x7fELF_X11")
            z.writestr("lib/arm64-v8a/librm11_engine_supervisor.so",
                       self.native.read_bytes())
            for name,bytes_ in GAME_COMPONENTS.items():
                z.writestr(name,b"not-trusted" if name==mutate else bytes_)
            if not missing_manifest:
                z.writestr("assets/engine/engine-native-manifest.json",
                           json.dumps(data))

    def test_valid_app_embeds_exact_hashes_and_keeps_engine_disabled(self):
        self.fakeapk()
        result=audit(self.apk,self.native,self.report)
        self.assertTrue(result["embedded_signed_engine_manifest_verified"])
        self.assertEqual(len(result["engine_component_hashes_verified"]),4)
        self.assertEqual(result["engine_activation"],"OFF")
        self.assertFalse(result["safe_to_release"])

    def test_missing_signed_apk_asset_is_rejected(self):
        self.fakeapk(missing_manifest=True)
        with self.assertRaisesRegex(ValueError,"MANIFEST_MISSING"):
            audit(self.apk,self.native,self.report)

    def test_altered_component_hash_is_rejected(self):
        self.fakeapk(mutate="assets/runtime/rm11-wine-stack.zip")
        with self.assertRaisesRegex(ValueError,"RUNTIME_BYTES_MODIFIED"):
            audit(self.apk,self.native,self.report)

    def test_unsafe_activation_request_is_rejected(self):
        self.fakeapk(alter_activation=True)
        with self.assertRaisesRegex(ValueError,"ACTIVATION_UNSAFE"):
            audit(self.apk,self.native,self.report)

    def test_generator_rejects_wrong_pinned_release(self):
        data=json.loads(self.report.read_text())
        data["baseline_apk_sha256"]="0"*64
        self.report.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"BASELINE_NOT_PINNED"):
            create(self.report,self.native,self.manifest)

    def test_supervisor_elf_must_match_generated_manifest(self):
        self.fakeapk()
        self.native.write_bytes(b"\x7fELF"+b"M"*6000)
        with self.assertRaisesRegex(ValueError,"SUPERVISOR_BINARY_CHANGED"):
            audit(self.apk,self.native,self.report)


if __name__=="__main__":
    unittest.main()
