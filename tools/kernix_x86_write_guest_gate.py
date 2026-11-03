"""Static x86 guest-byte contract for Android FEXCore write/getpid probe.

This validates exact guest bytes, instruction boundaries, RIP-relative message
pointer and two syscall offsets before compiling native Android code.
It is NOT an emulator, cannot validate runtime JIT, and never opens game files.
"""
from __future__ import annotations

import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "native-engine/android-host/kernix_fexcore_x86_64_write_bridge_probe.cpp"
MESSAGE = b"KERNIX_GUEST_WRITE_OK\n"
CODE_SIZE = 37
SYSCALL_OFFSETS = (22, 31)


def load_bytes(source: str) -> bytes:
    match = re.search(r"constexpr uint8_t GUEST_X86_64\[\] = \{(.*?)\};", source, re.S)
    if not match:
        raise ValueError("No fixed guest byte sequence")
    body = match.group(1)
    clean = re.sub(r"0x[0-9a-fA-F]{2}|[\s,]", "", body)
    if clean:
        raise ValueError("Unexpected token in guest byte array")
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", body))


def validate(payload: bytes) -> None:
    if len(payload) != CODE_SIZE + len(MESSAGE):
        raise ValueError("Fixed guest length changed")
    if payload[CODE_SIZE:] != MESSAGE:
        raise ValueError("Read-only mapped guest message changed")
    expected = {
        0: b"\xb8\x01\x00\x00\x00",           # mov eax, 1
        5: b"\xbf\x01\x00\x00\x00",           # mov edi, 1
        10: b"\x48\x8d\x35",                 # lea rsi,[rip+imm32]
        17: b"\xba" + bytes([len(MESSAGE), 0, 0, 0]), # mov edx, length
        22: b"\x0f\x05",                      # syscall write
        24: b"\x89\xc3",                      # mov ebx,eax
        26: b"\xb8\x27\x00\x00\x00",         # mov eax, 39
        31: b"\x0f\x05",                      # syscall getpid
        33: b"\x48\x01\xd8",                 # add rax,rbx
        36: b"\xf4",                            # hlt
    }
    for offset, data in expected.items():
        if payload[offset:offset + len(data)] != data:
            raise ValueError(f"Instruction mismatch at guest offset {offset}")
    # RIP following the 7-byte LEA is offset 17, message starts at 37.
    displacement = int.from_bytes(payload[13:17], "little", signed=True)
    if 17 + displacement != CODE_SIZE:
        raise ValueError("RIP-relative pointer escapes fixed guest message")
    if payload.count(b"\x0f\x05") != 2:
        raise ValueError("Unexpected number of guest syscall instructions")
    if SYSCALL_OFFSETS != (22, 31):
        raise ValueError("Guest trap offsets changed")


def main() -> None:
    payload = load_bytes(SOURCE.read_text())
    validate(payload)
    print("KERNIX_GUEST_WRITE_MEMORY_TWO_SYSCALL_BYTE_AND_RIP_CONTRACT_PASS")


if __name__ == "__main__":
    main()
