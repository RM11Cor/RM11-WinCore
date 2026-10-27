#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from patch_mesa_android_app_namespace import patch_mesa

MESON = """if with_android_stub
  stub_libs = []
  lib_names = ['hardware', 'log', 'nativewindow', 'sync']
  foreach lib : lib_names
    stub_libs += shared_library(lib, files(lib + '_stub.cpp'))
  endforeach
  dep_android = declare_dependency(link_with : stub_libs)
endif
"""
HARDWARE = """#include <hardware/hardware.h>
extern "C" {
int hw_get_module(const char *id, const struct hw_module_t **module)
{
   return 0;
}
}
"""


class MesaAndroidNamespacePatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.d = self.root / "src/android_stub"
        self.d.mkdir(parents=True)
        (self.d / "meson.build").write_text(MESON)
        (self.d / "hardware_stub.cpp").write_text(HARDWARE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_replace_shared_private_hal_with_honest_static_fallback(self):
        report = patch_mesa(self.root)
        m = (self.d / "meson.build").read_text()
        h = (self.d / "hardware_stub.cpp").read_text()
        self.assertIn("'rm11_legacy_hal_unavailable'", m)
        self.assertIn("lib_names = ['log', 'nativewindow', 'sync']", m)
        self.assertIn("return -ENOSYS;", h)
        self.assertIn("*module = nullptr;", h)
        self.assertFalse(report["hardware_gralloc_proved"])
        self.assertFalse(report["android_dlopen_proved"])

    def test_repeat_is_idempotent(self):
        patch_mesa(self.root)
        first = [(self.d / p).read_text()
                 for p in ("meson.build", "hardware_stub.cpp")]
        patch_mesa(self.root)
        self.assertEqual(first, [(self.d / p).read_text()
                                 for p in ("meson.build", "hardware_stub.cpp")])

    def test_unrecognized_mesa_layout_blocks_without_writing(self):
        m = self.d / "meson.build"
        m.write_text(MESON.replace("  stub_libs = []", "  stub_libs = other_deps"))
        with self.assertRaisesRegex(ValueError, "SOURCE_DRIFT"):
            patch_mesa(self.root)
        self.assertEqual((self.d / "hardware_stub.cpp").read_text(), HARDWARE)

    def test_unrecognized_hal_stub_blocks_without_writing(self):
        h = self.d / "hardware_stub.cpp"
        h.write_text(HARDWARE.replace("   return 0;", "   return -1;"))
        with self.assertRaisesRegex(ValueError, "SOURCE_DRIFT"):
            patch_mesa(self.root)
        self.assertEqual((self.d / "meson.build").read_text(), MESON)


if __name__ == "__main__":
    unittest.main()
