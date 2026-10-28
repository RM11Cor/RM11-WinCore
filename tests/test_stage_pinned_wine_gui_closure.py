"""Native Wine GUI closure gate unit tests (no game or device required)."""
import sys,unittest,tempfile,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_pinned_wine_gui_closure import (
    stage,ROOTS,PLATFORM_SONAMES,WINE_ALIAS_SONAMES,
    verify_elf,PINNED_APK_SHA
)
class PinnedGuiClosureTests(unittest.TestCase):
    def test_critical_modules_are_mandatory(self):
        required={"libwine_winex11.so","libwine_win32u.so",
                  "libX11.so","libXext.so","libxcb.so",
                  "librm11_freetype_core.so",
                  "libandroid-sysvshm.so"}
        self.assertTrue(required.issubset(ROOTS))
    def test_no_system_vulkan_driver_substitution(self):
        self.assertNotIn("libvulkan_freedreno.so",ROOTS)
        self.assertNotIn("libvulkan.so",ROOTS)
        self.assertIn("ntdll.so",WINE_ALIAS_SONAMES)
        self.assertIn("libc.so",PLATFORM_SONAMES)
    def test_wrong_source_hash_blocks_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            archive=p/"invalid.apk"
            with zipfile.ZipFile(archive,"w") as z:z.writestr("anything","not signed")
            target=p/"native"
            with self.assertRaisesRegex(ValueError,"SOURCE_SIGNED_PIN_MISMATCH"):
                stage(archive,target,p/"report.json")
            self.assertFalse(target.exists())
    def test_reject_invalid_native_elf(self):
        for data in [b"MZ"+b"0"*20000,b"\x7fELF"+b"0"*20000,b""]:
            with self.assertRaisesRegex(ValueError,"NOT_AARCH64_ET_DYN"):
                verify_elf(data,"libX11.so")
    def test_pinned_hash_shape(self):
        self.assertEqual(len(PINNED_APK_SHA),64)
        self.assertTrue(all(x in "0123456789abcdef" for x in PINNED_APK_SHA))
if __name__=="__main__":unittest.main()
