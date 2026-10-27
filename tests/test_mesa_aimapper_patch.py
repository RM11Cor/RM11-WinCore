#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from patch_mesa_android_aimapper import CHANGES, patch_mesa


class AimapperSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "mesa"
        self.impl = Path(self.temp.name) / "upstream.c"
        self.impl.write_bytes(b"/* SPDX-License-Identifier: MIT */\n" +
                              b"void *u_gralloc_aimapper_create(void) {return 0;}\n" +
                              b"/* Mesa Android IMapper5 implementation */\n" * 400)
        for name, (old, _) in CHANGES.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("prefix\n" + old + "\nsuffix\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_patches_source_and_preserves_provenance(self):
        result = patch_mesa(self.root, self.impl)
        self.assertTrue(result["static_integration_candidate"])
        self.assertFalse(result["safe_to_publish_apk"])
        self.assertEqual(result["source_spdx"], "MIT")
        for name, (_, new) in CHANGES.items():
            self.assertIn(new, (self.root / name).read_text())
        self.assertEqual(
            (self.root / "src/util/u_gralloc/u_gralloc_aimapper.c").read_bytes(),
            self.impl.read_bytes())

    def test_idempotent_and_never_duplicates(self):
        first = patch_mesa(self.root, self.impl)
        self.assertEqual(first, patch_mesa(self.root, self.impl))

    def test_missing_anchor_must_not_partially_modify_files(self):
        broken = self.root / "src/util/u_gralloc/u_gralloc_internal.h"
        broken.write_text("upstream refactored")
        before = {p: (self.root / p).read_bytes() for p in CHANGES}
        with self.assertRaisesRegex(ValueError, "SOURCE_DRIFT"):
            patch_mesa(self.root, self.impl)
        self.assertEqual(before, {p: (self.root / p).read_bytes() for p in CHANGES})

    def test_rejects_missing_spdx_mit(self):
        self.impl.write_bytes(self.impl.read_bytes().replace(
            b"SPDX-License-Identifier: MIT", b"SPDX-License-Identifier: unknown"))
        with self.assertRaisesRegex(ValueError, "LICENSE_NOT_VERIFIED"):
            patch_mesa(self.root, self.impl)

    def test_legacy_multilayer_fields_dropped_fail_closed(self):
        stanza = (b"   /* vk_gralloc_to_drm_explicit_layout() metadata */\n"
                  b"   uint64_t layer_count = 0;\n"
                  b"   if (md_scalar(gr, hnd->handle, SMT_LAYER_COUNT, &layer_count, 8))\n"
                  b"      out->layer_count = layer_count;\n"
                  b"   uint64_t alloc_size = 0;\n"
                  b"   if (md_scalar(gr, hnd->handle, SMT_ALLOCATION_SIZE, &alloc_size, 8))\n"
                  b"      out->alloc_size = alloc_size;\n"
                  b"   ret = 0;\n")
        self.impl.write_bytes(self.impl.read_bytes() + stanza)
        report = patch_mesa(self.root, self.impl)
        result = (self.root / "src/util/u_gralloc/u_gralloc_aimapper.c").read_bytes()
        self.assertTrue(report["mesa_26_2_single_layer_compat_applied"])
        self.assertNotIn(b"out->layer_count", result)
        self.assertNotIn(b"out->alloc_size", result)
        self.assertIn(b"ret = 0;", result)

    def test_incomplete_metadata_section_refuses_source(self):
        self.impl.write_bytes(self.impl.read_bytes() +
                              b"\nout->layer_count = 2;\n")
        with self.assertRaisesRegex(ValueError, "LATER_MESA_FIELDS_DRIFT"):
            patch_mesa(self.root, self.impl)

    def test_does_not_replace_different_aimapper_source(self):
        target = self.root / "src/util/u_gralloc/u_gralloc_aimapper.c"
        target.write_bytes(b"conflict")
        with self.assertRaisesRegex(ValueError, "PREEXISTING_CONFLICT"):
            patch_mesa(self.root, self.impl)


if __name__ == "__main__":
    unittest.main()
