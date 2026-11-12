#ifndef FH5_X86_CF_CORE_H
#define FH5_X86_CF_CORE_H
#include <stddef.h>
#include <stdint.h>

#define FH5_CF_SAMPLE_MAX 512
#define FH5_CF_MAX_INSNS 16
#define FH5_CF_MNEMONIC_MAX 24

typedef struct {
    int decode_ok;
    size_t decoded_count, decoded_bytes;
    size_t first_block_count, first_block_bytes;
    size_t call_count, branch_count, return_count, memory_operand_count;
    char linear_mnemonics[FH5_CF_MAX_INSNS][FH5_CF_MNEMONIC_MAX];
    char first_block_mnemonics[FH5_CF_MAX_INSNS][FH5_CF_MNEMONIC_MAX];
    int transfer_found;
    size_t transfer_insn_index, transfer_offset, transfer_length;
    char transfer_kind[24];
    char target_kind[24];
    int direct_target_valid;
    uint64_t direct_target_rva;
    int target_within_sample;
    int target_within_image;
} fh5_cf_result;

/* Only decode, never copy to executable memory or call original code. */
int fh5_cf_analyze(const uint8_t *sample, size_t n,
                   uint64_t start_rva,uint64_t image_size,
                   fh5_cf_result *out);
#endif
