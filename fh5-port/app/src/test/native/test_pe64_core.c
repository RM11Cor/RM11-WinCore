/* FH5 P2 native core host test (not Android device execution). */
#include "pe64_micro_core.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

static void w16(uint8_t *b,size_t p,uint16_t v) {
    b[p]=(uint8_t)v; b[p+1]=(uint8_t)(v>>8);
}
static void w32(uint8_t *b,size_t p,uint32_t v) {
    for (unsigned i=0;i<4;i++) b[p+i]=(uint8_t)(v>>(i*8));
}
static void make_pe(uint8_t b[1024]) {
    memset(b,0,1024);
    b[0]='M';b[1]='Z';w32(b,0x3c,0x80);
    b[0x80]='P';b[0x81]='E';
    w16(b,0x84,0x8664);w16(b,0x86,1);w16(b,0x94,0xf0);
    w16(b,0x98,0x20b);w32(b,0x98+16,0x1000);
    w32(b,0x98+108,16);
    size_t s=0x98+0xf0;
    w32(b,s+8,0x200);w32(b,s+12,0x1000);
    w32(b,s+16,0x200);w32(b,s+20,0x200);w32(b,s+36,0x60000020);
    const uint8_t op[]={0xb8,2,0,0,0,0x05,40,0,0,0,0xc3};
    memcpy(b+0x200,op,sizeof(op));
}
int main(void) {
    uint8_t buf[1024];
    rm11_micro_program p;
    make_pe(buf);
    assert(rm11_micro_parse_pe64(buf,sizeof(buf),&p)==RM11_MICRO_OK);
    assert(p.x86_bytes==11);
    assert(p.entry_rva==0x1000);
    assert(p.word_count>=6);
    assert(p.words[p.word_count-1]==0xd65f03c0u);
    puts("PASS: real x86->ARM64 output instruction sequence translated");
    buf[0]=0;
    assert(rm11_micro_parse_pe64(buf,sizeof(buf),&p)==RM11_MICRO_BAD_PE);
    make_pe(buf);
    w16(buf,0x84,0x14c);
    assert(rm11_micro_parse_pe64(buf,sizeof(buf),&p)==RM11_MICRO_UNSUPPORTED_PE);
    make_pe(buf);
    w32(buf,0x98+120,0x1000);
    assert(rm11_micro_parse_pe64(buf,sizeof(buf),&p)==RM11_MICRO_UNSUPPORTED_PE);
    make_pe(buf);
    buf[0x200]=0xCC;
    assert(rm11_micro_parse_pe64(buf,sizeof(buf),&p)==RM11_MICRO_UNSUPPORTED_X86);
    puts("PASS: PE parsing rejects wrong architecture, imports, unsupported instructions");
    return 0;
}
