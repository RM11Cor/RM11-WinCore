import io
import struct
import unittest
import zipfile

from tools.audit_pinned_wine_bus import audit


def make_elf():
    b = bytearray(4096)
    b[:4] = b"\x7fELF"
    b[4:6] = b"\x02\x01"
    struct.pack_into("<H", b, 18, 183)
    return bytes(b)


def make_pe(machine):
    b = bytearray(4096)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3c, 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", b, 0x84, machine)
    return bytes(b)


def bundle(missing=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipf:
        sources = {
            "lib/wine/aarch64-unix/winebus.so": make_elf(),
            "lib/wine/aarch64-windows/winebus.sys": make_pe(0xAA64),
            "lib/wine/i386-windows/winebus.sys": make_pe(0x014c),
        }
        for k, v in sources.items():
            if k != missing:
                zipf.writestr(k, v)
    return buffer.getvalue()


class AuditPinnedWineBusTest(unittest.TestCase):
    def test_arch_and_fails_closed(self):
        data = audit(bundle())
        self.assertEqual([x["machine"] for x in data["winebus_files"]],
                         ["AARCH64_ELF64", "ARM64", "I386"])
        self.assertFalse(data["source_revision_verified"])
        self.assertFalse(data["rm11_hid_adapter_packaging_allowed"])
        self.assertEqual(len(data["winebus_files"]), 3)

    def test_missing_pe_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing_required_winebus"):
            audit(bundle("lib/wine/i386-windows/winebus.sys"))

    def test_bad_elf_rejected(self):
        b = bytearray(make_elf())
        b[18] = 0
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            z.writestr("lib/wine/aarch64-unix/winebus.so", b)
            z.writestr("lib/wine/aarch64-windows/winebus.sys", make_pe(0xAA64))
            z.writestr("lib/wine/i386-windows/winebus.sys", make_pe(0x014c))
        with self.assertRaisesRegex(ValueError, "native_winebus_must_be_aarch64"):
            audit(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
