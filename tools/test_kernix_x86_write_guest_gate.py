"""Fail-closed regression gates for the fixed Android FEXCore guest."""
import unittest

from kernix_x86_write_guest_gate import CODE_SIZE, MESSAGE, SOURCE, load_bytes, validate


class FixedGuestMemoryBridgeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = load_bytes(SOURCE.read_text())

    def test_rejects_changed_guest_message(self):
        p = bytearray(self.original)
        p[CODE_SIZE] ^= 1
        with self.assertRaises(ValueError):
            validate(bytes(p))

    def test_original_fixed_guest(self):
        validate(self.original)

    def test_rejects_changed_guest_memory_pointer(self):
        p = bytearray(self.original)
        p[13] ^= 1
        with self.assertRaises(ValueError):
            validate(bytes(p))

    def test_rejects_extra_or_changed_syscall(self):
        p = bytearray(self.original)
        p[22] = 0x90
        with self.assertRaises(ValueError):
            validate(bytes(p))
        p = bytearray(self.original)
        p[31] = 0x90
        with self.assertRaises(ValueError):
            validate(bytes(p))

    def test_rejects_out_of_bounds_message(self):
        p = bytearray(self.original)
        p.append(0)
        with self.assertRaises(ValueError):
            validate(bytes(p))
        p = self.original[:CODE_SIZE] + MESSAGE[:-1]
        with self.assertRaises(ValueError):
            validate(p)

    def test_rejects_changed_guest_call_arguments(self):
        p = bytearray(self.original)
        p[6] = 2  # guest stdout fd must be 1
        with self.assertRaises(ValueError):
            validate(bytes(p))
        p = bytearray(self.original)
        p[18] = len(MESSAGE) + 1  # guest buffer cannot be extended
        with self.assertRaises(ValueError):
            validate(bytes(p))

    def test_rejects_malformed_guest_byte_array(self):
        with self.assertRaises(ValueError):
            load_bytes('constexpr uint8_t GUEST_X86_64[] = {0x01, unresolved};')
        with self.assertRaises(ValueError):
            load_bytes('no executable bytes')


if __name__ == "__main__":
    unittest.main()
