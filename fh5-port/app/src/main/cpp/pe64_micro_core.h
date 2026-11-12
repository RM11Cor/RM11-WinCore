#ifndef RM11_PE64_MICRO_CORE_H
#define RM11_PE64_MICRO_CORE_H
#include <stddef.h>
#include <stdint.h>
#define RM11_MICRO_MAX_FILE (512u * 1024u)
#define RM11_MICRO_MAX_ARM_WORDS 128u

typedef enum {
  RM11_MICRO_OK = 0,
  RM11_MICRO_BAD_PE = 1,
  RM11_MICRO_UNSUPPORTED_PE = 2,
  RM11_MICRO_UNSUPPORTED_X86 = 3,
  RM11_MICRO_TOO_LARGE = 4,
  RM11_MICRO_NO_RET = 5,
  RM11_MICRO_JIT_DENIED = 6
} rm11_micro_status;

typedef struct {
  uint32_t words[RM11_MICRO_MAX_ARM_WORDS];
  size_t word_count;
  size_t x86_bytes;
  uint32_t entry_rva;
} rm11_micro_program;

rm11_micro_status rm11_micro_translate_x86(const uint8_t *x86, size_t length,
                                             rm11_micro_program *out);
rm11_micro_status rm11_micro_parse_pe64(const uint8_t *pe, size_t length,
                                        rm11_micro_program *out);
const char *rm11_micro_status_name(rm11_micro_status status);
#endif
