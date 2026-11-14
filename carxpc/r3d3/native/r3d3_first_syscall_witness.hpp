// SPDX-License-Identifier: MIT
// CarX R3D3: read-only verification of a syscall observed from a genuine
// FEXCore SyscallHandler callback. Does NOT execute Wine by itself.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace carx_r3d3 {
constexpr uint32_t kMagic = 0x33443352; // R3D3, little endian
constexpr uint32_t kVersion = 2;
constexpr uint32_t kObservedAtRip = 1;
constexpr uint32_t kObservedBeforeRip = 2;

struct Load {
  uint64_t bias;    // pinned guest base, not a native host pointer
  uint64_t vaddr;   // original ELF p_vaddr
  uint64_t offset;  // original ELF p_offset
  uint64_t filesz;  // original ELF p_filesz
  bool rx;          // source PT_LOAD had PF_X, verified separately
};

// Fixed wire layout, written only by native FEX syscall callback.
// A matching record remains diagnostic evidence, not signed attestation.
struct Record {
  uint32_t magic, version;
  uint64_t session_nonce;
  uint64_t guest_syscall_number;
  uint64_t opcode_guest_rip;
  uint64_t callback_guest_rip;
  uint64_t source_file_offset;
  uint32_t interpretation;
  uint32_t reserved;
};
static_assert(sizeof(Record) == 56, "R3D3 wire layout changed");

struct Match {
  bool found = false;
  uint64_t offset = 0;
  uint64_t opcode_rip = 0;
};

inline Match find_source_syscall(const uint8_t* image, size_t image_len,
                                const Load* loads, size_t load_count,
                                uint64_t opcode_rip) noexcept {
  Match out{};
  if (!image || !loads || load_count == 0 || load_count > 96) return out;
  for (size_t i = 0; i < load_count; ++i) {
    const Load& l = loads[i];
    if (!l.rx || l.vaddr > UINT64_MAX - l.bias) continue;
    const uint64_t start = l.bias + l.vaddr;
    if (opcode_rip < start || l.filesz < 2 ||
        l.offset > image_len || l.filesz > image_len - l.offset) continue;
    const uint64_t delta = opcode_rip - start;
    if (delta > l.filesz - 2) continue;
    const uint64_t off = l.offset + delta;
    if (image[off] != 0x0F || image[off + 1] != 0x05) continue;
    if (out.found) return Match{}; // overlapping RX loads: ambiguous source
    out = Match{true, off, opcode_rip};
  }
  return out;
}

// FEX versions may expose a callback RIP pointing at the syscall itself or
// immediately after it. Accept exactly ONE of those interpretations, never
// guess or label a neighboring byte sequence as the executed syscall.
inline bool make_record(const uint8_t* ldso, size_t source_len,
                        const Load* loads, size_t load_count,
                        uint64_t callback_rip, uint64_t syscall_no,
                        uint64_t session_nonce, Record* result) noexcept {
  if (!result || !session_nonce || !callback_rip || syscall_no > 0xFFFFFFFFu)
    return false;
  const Match at = find_source_syscall(ldso, source_len, loads, load_count, callback_rip);
  const Match prior = callback_rip >= 2
      ? find_source_syscall(ldso, source_len, loads, load_count, callback_rip - 2)
      : Match{};
  if (at.found == prior.found) return false; // none or ambiguous
  const Match& chosen = at.found ? at : prior;
  *result = Record{kMagic, kVersion, session_nonce, syscall_no,
                   chosen.opcode_rip, callback_rip, chosen.offset,
                   at.found ? kObservedAtRip : kObservedBeforeRip, 0};
  return true;
}

// Android tests must run in exact service subprocess, not UI process.
// The native layer should ALSO validate process identity from /proc/self/cmdline.
inline bool exact_service_process(const char* cmdline, size_t len) noexcept {
  static constexpr char kExpected[] = "com.r4.carxpc:r3d3_probe";
  constexpr size_t want = sizeof(kExpected) - 1;
  return cmdline && len == want &&
         std::memcmp(cmdline, kExpected, want) == 0;
}
} // namespace carx_r3d3
