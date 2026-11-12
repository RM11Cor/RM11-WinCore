#include "x86_cf_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_first_call(void) {
    /* SUB RSP,0x28; CALL +5 (lands at offset 14); five NOPs;
       XOR EAX,EAX; RET. The 5 NOPs are fall-through, not assumed
       dynamically executed by this read-only analyzer. */
    const uint8_t code[]={
       0x48,0x83,0xec,0x28,
       0xe8,0x05,0x00,0x00,0x00,
       0x90,0x90,0x90,0x90,0x90,
       0x31,0xc0,0xc3
    };
    fh5_cf_result r;
    assert(fh5_cf_analyze(code,sizeof(code),0x2000,0x5000,&r)==0);
    assert(r.decode_ok);
    assert(r.transfer_found);
    assert(r.transfer_insn_index==1);
    assert(r.first_block_count==2);
    assert(r.first_block_bytes==9);
    assert(r.transfer_offset==4);
    assert(strcmp(r.transfer_kind,"call")==0);
    assert(strcmp(r.target_kind,"direct")==0);
    assert(r.direct_target_valid);
    assert(r.direct_target_rva==0x200e);
    assert(r.target_within_sample);
    assert(r.target_within_image);
    assert(strcmp(r.first_block_mnemonics[0],"sub")==0);
    assert(strcmp(r.first_block_mnemonics[1],"call")==0);
    assert(r.call_count==1);
    puts("PASS bounded first call analysis and direct target RVA");
}
static void test_indirect_call(void) {
    const uint8_t code[]={0xff,0xd0,0xc3}; /* CALL RAX; RET */
    fh5_cf_result r;
    assert(fh5_cf_analyze(code,sizeof(code),0x1000,0x3000,&r)==0);
    assert(r.transfer_found);
    assert(strcmp(r.transfer_kind,"call")==0);
    assert(strcmp(r.target_kind,"register_indirect")==0);
    assert(!r.direct_target_valid);
    puts("PASS indirect target never invented");
}
static void test_jumps(void) {
    const uint8_t code[]={0xeb,0x02,0x90,0x90,0xc3};
    fh5_cf_result r;
    assert(fh5_cf_analyze(code,sizeof(code),0x3000,0x8000,&r)==0);
    assert(strcmp(r.transfer_kind,"unconditional_jump")==0);
    assert(r.direct_target_rva==0x3004);
    assert(r.first_block_count==1);
    assert(r.first_block_bytes==2);
    puts("PASS first jump target classified");
}
static void test_outside_module(void) {
    const uint8_t code[]={0xe8,0x00,0x10,0x00,0x00,0xc3};
    fh5_cf_result r;
    assert(fh5_cf_analyze(code,sizeof(code),0x1000,0x2000,&r)==0);
    assert(r.transfer_found);
    assert(!r.direct_target_valid);
    assert(strcmp(r.target_kind,"direct_outside_image")==0);
    puts("PASS out-of-image target not followed");
}
static void test_bounds(void) {
    fh5_cf_result r;
    uint8_t byte=0x90;
    assert(fh5_cf_analyze(&byte,0,0,0x1000,&r)<0);
    assert(fh5_cf_analyze(&byte,1,0x1000,0x1000,&r)<0);
    assert(fh5_cf_analyze(NULL,1,0,0x1000,&r)<0);
    assert(fh5_cf_analyze(&byte,513,0,0x1000,&r)<0);
    const uint8_t undecodeable[]={0x0f};
    assert(fh5_cf_analyze(undecodeable,sizeof(undecodeable),0,0x1000,&r)<0);
    puts("PASS malformed/truncated/out-of-budget decode rejected");
}

static void test_deep_target_stack_and_simd(void) {
    /* 24 register pushes, MOVUPD XMM0,XMM1, then first CALL.
     * A 16-insn scan would fail to locate the first control transfer. */
    uint8_t code[64];
    memset(code,0x90,sizeof(code));
    for(int i=0;i<24;i++)code[i]=0x50;
    code[24]=0x66;code[25]=0x0f;code[26]=0x10;code[27]=0xc1;
    code[28]=0xe8;code[29]=0;code[30]=0;code[31]=0;code[32]=0;
    code[33]=0xc3;
    fh5_cf_result r;
    assert(fh5_cf_analyze(code,sizeof(code),0x5000,0x7000,&r)==0);
    assert(r.push_count==24);
    assert(r.pop_count==0);
    assert(r.vector_xmm_count>=1);
    assert(r.vector_ymm_count==0 && r.vector_zmm_count==0);
    assert(r.transfer_found);
    assert(r.first_block_count==26);
    assert(r.first_block_bytes==33);
    assert(r.direct_target_rva==0x5021);
    assert(r.decoded_count>16);
    assert(strcmp(r.first_block_mnemonics[24],"movupd")==0);
    assert(strcmp(r.first_block_mnemonics[25],"call")==0);
    puts("PASS >16 instruction deeper target, XMM categorization, stack pushes and call target");
}

int main(void) {
    test_first_call();
    test_indirect_call();
    test_jumps();
    test_outside_module();
    test_bounds();
    test_deep_target_stack_and_simd();
    puts("ALL P2.6 control-flow tests PASS");
    return 0;
}
