/* Educational, bounded PE32+ entry-point translator.
 * NOT FEXCore, NOT a Windows loader, and NOT support for real games.
 * Only a six-opcode, register-only subset is translated. No syscalls/imports.
 */
#include "pe64_micro_core.h"
#include <string.h>

static int within(size_t total, size_t start, size_t count) {
  return start <= total && count <= total - start;
}
static uint16_t u16(const uint8_t *p) {
  return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}
static uint32_t u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int emit(rm11_micro_program *out, uint32_t opcode) {
  if (out->word_count >= RM11_MICRO_MAX_ARM_WORDS) return 0;
  out->words[out->word_count++] = opcode;
  return 1;
}
/* MOVZ Wd, low16 and MOVK Wd, high16 (x86 EAX is a 32-bit register). */
static int emit_imm32(rm11_micro_program *out, unsigned rd, uint32_t value) {
  return emit(out, 0x52800000u | ((value & 0xffffu) << 5) | rd) &&
      emit(out, 0x72a00000u | (((value >> 16) & 0xffffu) << 5) | rd);
}
rm11_micro_status rm11_micro_translate_x86(const uint8_t *x86, size_t length,
                                             rm11_micro_program *out) {
  if (!x86 || !out || length == 0) return RM11_MICRO_UNSUPPORTED_X86;
  memset(out, 0, sizeof(*out));
  size_t pc = 0;
  unsigned instructions = 0;
  while (pc < length && instructions++ < 32) {
    uint8_t op = x86[pc++];
    switch (op) {
      case 0xB8: /* mov eax, imm32 */
        if (!within(length, pc, 4)) return RM11_MICRO_UNSUPPORTED_X86;
        if (!emit_imm32(out, 0, u32(x86 + pc))) return RM11_MICRO_TOO_LARGE;
        pc += 4;
        break;
      case 0x05: /* add eax, imm32 */
      case 0x2D: /* sub eax, imm32 */
        if (!within(length, pc, 4)) return RM11_MICRO_UNSUPPORTED_X86;
        if (!emit_imm32(out, 1, u32(x86 + pc)) ||
            !emit(out, op == 0x05 ? 0x0b010000u : 0x4b010000u))
          return RM11_MICRO_TOO_LARGE;
        pc += 4;
        break;
      case 0x31: /* xor eax, eax only */
        if (!within(length, pc, 1) || x86[pc++] != 0xc0) return RM11_MICRO_UNSUPPORTED_X86;
        if (!emit_imm32(out, 0, 0)) return RM11_MICRO_TOO_LARGE;
        break;
      case 0x90: /* nop */
        if (!emit(out, 0xd503201fu)) return RM11_MICRO_TOO_LARGE;
        break;
      case 0xC3: /* ret */
        if (!emit(out, 0xd65f03c0u)) return RM11_MICRO_TOO_LARGE;
        out->x86_bytes = pc;
        return RM11_MICRO_OK;
      default:
        return RM11_MICRO_UNSUPPORTED_X86;
    }
  }
  return RM11_MICRO_NO_RET;
}

rm11_micro_status rm11_micro_parse_pe64(const uint8_t *pe, size_t length,
                                        rm11_micro_program *out) {
  if (!pe || !out || length < 256) return RM11_MICRO_BAD_PE;
  if (length > RM11_MICRO_MAX_FILE) return RM11_MICRO_TOO_LARGE;
  if (pe[0] != 'M' || pe[1] != 'Z') return RM11_MICRO_BAD_PE;
  uint32_t pe_off = u32(pe + 0x3c);
  if (!within(length, pe_off, 24) || memcmp(pe + pe_off, "PE\0\0", 4)) return RM11_MICRO_BAD_PE;
  const uint8_t *coff = pe + pe_off + 4;
  if (u16(coff) != 0x8664) return RM11_MICRO_UNSUPPORTED_PE;
  uint16_t num_sections = u16(coff + 2);
  uint16_t opt_size = u16(coff + 16);
  if (!num_sections || num_sections > 64 || opt_size < 112 ||
      !within(length, (size_t)pe_off + 24, opt_size)) return RM11_MICRO_BAD_PE;
  const uint8_t *opt = pe + pe_off + 24;
  if (u16(opt) != 0x20b) return RM11_MICRO_UNSUPPORTED_PE;
  /* Real Windows imports require a Windows runtime; explicitly reject. */
  uint32_t directories = u32(opt + 108);
  if (directories > 1) {
    if (opt_size < 136) return RM11_MICRO_BAD_PE;
    if (u32(opt + 120) != 0 || u32(opt + 124) != 0) return RM11_MICRO_UNSUPPORTED_PE;
  }
  uint32_t entry_rva = u32(opt + 16);
  size_t section_table = (size_t)pe_off + 24 + opt_size;
  if (!entry_rva || !within(length, section_table, (size_t)num_sections * 40))
    return RM11_MICRO_BAD_PE;
  for (uint16_t i = 0; i < num_sections; ++i) {
    const uint8_t *s = pe + section_table + (size_t)i * 40;
    uint32_t virtual_size = u32(s + 8);
    uint32_t virtual_address = u32(s + 12);
    uint32_t raw_size = u32(s + 16);
    uint32_t raw_offset = u32(s + 20);
    uint32_t flags = u32(s + 36);
    if (entry_rva < virtual_address) continue;
    uint32_t relative = entry_rva - virtual_address;
    if (!(flags & 0x20000000u) || relative >= virtual_size || relative >= raw_size)
      continue;
    if (!within(length, raw_offset, raw_size)) return RM11_MICRO_BAD_PE;
    size_t start = (size_t)raw_offset + relative;
    size_t n = (size_t)raw_size - relative;
    if (n > 256) n = 256;
    rm11_micro_status status = rm11_micro_translate_x86(pe + start, n, out);
    if (status == RM11_MICRO_OK) out->entry_rva = entry_rva;
    return status;
  }
  return RM11_MICRO_UNSUPPORTED_PE;
}

const char *rm11_micro_status_name(rm11_micro_status s) {
  switch (s) {
    case RM11_MICRO_OK: return "translated";
    case RM11_MICRO_BAD_PE: return "invalid-or-truncated-pe";
    case RM11_MICRO_UNSUPPORTED_PE: return "requires-real-windows-loader";
    case RM11_MICRO_UNSUPPORTED_X86: return "unsupported-x86-instruction";
    case RM11_MICRO_TOO_LARGE: return "input-too-large";
    case RM11_MICRO_NO_RET: return "no-return-in-bounded-code";
    case RM11_MICRO_JIT_DENIED: return "android-jit-denied";
    default: return "unknown";
  }
}
