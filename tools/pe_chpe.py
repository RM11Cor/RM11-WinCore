"""Bounded PE32+ CHPE (ARM64EC hybrid) metadata reader.

The final linked ARM64EC image normally has IMAGE_FILE_MACHINE_AMD64
(0x8664) in its COFF header. ARM64EC identity is carried by the load
configuration CHPEMetadataPointer, not the 0xA641 object-file machine ID.
See Microsoft Windows ARM64EC documentation and Wine's has_chpe_metadata().
"""
import struct

MAX_PE_BYTES = 128 * 1024 * 1024


def _u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("TRUNCATED_WORD")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("TRUNCATED_DWORD")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("TRUNCATED_QWORD")
    return struct.unpack_from("<Q", data, offset)[0]


def inspect_arm64ec(image):
    """Return metadata status without claiming the FEX translation works."""
    try:
        if len(image) > MAX_PE_BYTES:
            raise ValueError("OVERSIZED_IMAGE")
        if image[:2] != b"MZ" or len(image) < 0x100:
            raise ValueError("NOT_A_PE_IMAGE")
        pe = _u32(image, 0x3c)
        if pe < 0x40 or pe + 24 >= len(image) or image[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("INVALID_PE_HEADER")
        machine = _u16(image, pe + 4)
        if machine != 0x8664:
            raise ValueError("NOT_LINKED_AMD64_HYBRID")
        sections = _u16(image, pe + 6)
        size_of_optional = _u16(image, pe + 20)
        opt = pe + 24
        if _u16(image, opt) != 0x20b:
            raise ValueError("NOT_PE32_PLUS")
        image_base = _u64(image, opt + 24)
        if _u32(image, opt + 108) <= 10 or size_of_optional < 112 + 11 * 8:
            raise ValueError("NO_LOAD_CONFIG_DIRECTORY")
        config_rva = _u32(image, opt + 112 + 10 * 8)
        config_size = _u32(image, opt + 112 + 10 * 8 + 4)
        if not config_rva or config_size < 0xd0:
            raise ValueError("LOAD_CONFIG_TOO_SHORT")
        if sections < 1 or sections > 96 or size_of_optional > 4096:
            raise ValueError("INVALID_SECTION_TABLE")
        section_table = opt + size_of_optional

        def rva_to_file(rva, size):
            for i in range(sections):
                section = section_table + 40 * i
                virtual_size = _u32(image, section + 8)
                virtual_address = _u32(image, section + 12)
                raw_size = _u32(image, section + 16)
                raw_ptr = _u32(image, section + 20)
                if (rva >= virtual_address and
                        rva + size <= virtual_address + min(virtual_size, raw_size)):
                    offset = raw_ptr + rva - virtual_address
                    if offset + size <= len(image):
                        return offset
            raise ValueError("RVA_OUTSIDE_FILE_SECTIONS")

        config_off = rva_to_file(config_rva, 0xd0)
        own_size = _u32(image, config_off)
        if own_size < 0xd0:
            raise ValueError("LOAD_CONFIG_STRUCTURE_TOO_SHORT")
        # IMAGE_LOAD_CONFIG_DIRECTORY64.CHPEMetadataPointer = +0xC8.
        metadata_va = _u64(image, config_off + 0xc8)
        if not metadata_va or metadata_va < image_base:
            raise ValueError("CHPE_METADATA_POINTER_ABSENT")
        meta = rva_to_file(metadata_va - image_base, 16)
        version = _u32(image, meta)
        if version not in (1, 2):
            raise ValueError("CHPE_METADATA_VERSION_UNEXPECTED")
        return {
            "chpe_metadata": "PRESENT",
            "chpe_version": version,
            "arm64ec_abi_header": "LINKED_AMD64_WITH_CHPE",
            "abi_ok": True,
        }
    except (ValueError, OverflowError, struct.error) as exc:
        return {
            "chpe_metadata": "ABSENT_OR_INVALID",
            "reason": str(exc),
            "abi_ok": False,
        }
