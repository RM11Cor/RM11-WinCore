#include "pe64_micro_core.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks = 0;
static void expect(int value, const char *reason) {
  if (!value) { fprintf(stderr, "FAILED test: %s\n", reason); exit(1); }
  ++checks;
}
static uint32_t emulate_generated_arm(const rm11_micro_program *p) {
  uint32_t w[2] = {0, 0};
  for (size_t i=0;i<p->word_count;i++) {
    uint32_t v=p->words[i], rd=v & 0x1fu;
    if ((v & 0xff800000u) == 0x52800000u) { if (rd > 1) return 0; w[rd]=(v>>5)&0xffffu; }
    else if ((v & 0xff800000u) == 0x72800000u) { if (rd > 1) return 0; w[rd]=(w[rd] & 0xffffu)|(((v>>5)&0xffffu)<<16); }
    else if (v == 0x0b010000u) w[0]+=w[1];
    else if (v == 0x4b010000u) w[0]-=w[1];
    else if (v == 0xd503201fu) {}
    else if (v == 0xd65f03c0u) return w[0];
    else return 0;
  }
  return 0;
}
static void put32(uint8_t *p, uint32_t val){for(int j=0;j<4;j++)p[j]=(uint8_t)(val>>(8*j));}
int main(int argc, char **argv) {
  if (argc!=2) return 2;
  FILE *f=fopen(argv[1],"rb"); expect(f!=NULL, "fixture exists");
  uint8_t p[1024]; expect(fread(p,1,sizeof(p),f)==sizeof(p), "fixture length"); fclose(f);
  rm11_micro_program program;
  expect(rm11_micro_parse_pe64(p,sizeof(p),&program)==RM11_MICRO_OK, "valid PE64 parsed");
  expect(program.entry_rva==0x1000, "entry RVA detected");
  expect(program.x86_bytes==16, "real x86 bytes recognized");
  expect(program.word_count>0, "native ARM64 words emitted");
  expect(emulate_generated_arm(&program)==42, "translated ARM64 yields 42");
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q));q[0]=0;
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_BAD_PE,"bad MZ rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); q[0x84]=0x4c; q[0x85]=0x01;
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_UNSUPPORTED_PE,"32bit PE rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); put32(q+0x3c,1020);
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_BAD_PE,"unsafe PE offset rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); put32(q+0x98+120,0x1500);
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_UNSUPPORTED_PE,"DLL imports rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); q[0x200]=0xe8;
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_UNSUPPORTED_X86,"unknown branch rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); put32(q+0x98+16,0x70000000);
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_UNSUPPORTED_PE,"unmapped entry rejected"); }
  { uint8_t q[sizeof(p)]; memcpy(q,p,sizeof(q)); q[0x200+15]=0x90;
    expect(rm11_micro_parse_pe64(q,sizeof(q),&program)==RM11_MICRO_UNSUPPORTED_X86,"no RET with trailing padding rejected"); }
  { uint8_t x[]={0x31,0xc0,0xB8,0x2a,0,0,0,0x90,0xc3};
    expect(rm11_micro_translate_x86(x,sizeof(x),&program)==RM11_MICRO_OK,"XOR/MOV/NOP/RET supported");
    expect(emulate_generated_arm(&program)==42,"xor path computes 42"); }
  { uint8_t x[]={0xB8,0xff,0xff,0xff,0xff,0x05,0x01,0,0,0,0xc3};
    expect(rm11_micro_translate_x86(x,sizeof(x),&program)==RM11_MICRO_OK,"carry add translates");
    expect(emulate_generated_arm(&program)==0,"32bit register wrap matches x86"); }
  { uint8_t x[]={0xB8,0x01};
    expect(rm11_micro_translate_x86(x,sizeof(x),&program)==RM11_MICRO_UNSUPPORTED_X86,"truncated MOV rejected"); }
  expect(rm11_micro_parse_pe64(p,12,&program)==RM11_MICRO_BAD_PE,"truncated PE rejected");
  expect(rm11_micro_parse_pe64(p,RM11_MICRO_MAX_FILE+1,&program)==RM11_MICRO_TOO_LARGE,"large input rejected before dereference");
  printf("RM11 v2.4.15: %d host checks OK\n",checks);
  return 0;
}
