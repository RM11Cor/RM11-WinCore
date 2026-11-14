#include "../native/r3d3_first_syscall_witness.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
using namespace carx_r3d3;
int main() {
  std::array<uint8_t,128> source{};
  source[0x23]=0x0F; source[0x24]=0x05;
  Load l{0x4100000000ULL,0x1000,0x20,64,true};
  const uint64_t rip=0x4100001003ULL;
  Record r{};
  assert(make_record(source.data(),source.size(),&l,1,rip+2,257,55,&r));
  assert(r.magic==kMagic && r.version==kVersion && r.guest_syscall_number==257);
  assert(r.interpretation==kObservedBeforeRip && r.opcode_guest_rip==rip);
  assert(r.source_file_offset==0x23 && r.session_nonce==55);
  assert(make_record(source.data(),source.size(),&l,1,rip,257,55,&r));
  assert(r.interpretation==kObservedAtRip);
  assert(!make_record(source.data(),source.size(),&l,1,rip+3,257,55,&r));
  assert(!make_record(source.data(),source.size(),&l,1,rip+2,257,0,&r));
  assert(!make_record(source.data(),source.size(),&l,1,rip+2,0x100000000ULL,55,&r));
  Load nonrx=l;nonrx.rx=false;
  assert(!make_record(source.data(),source.size(),&nonrx,1,rip+2,257,55,&r));
  Load overflow=l;overflow.bias=UINT64_MAX;
  assert(!make_record(source.data(),source.size(),&overflow,1,rip+2,257,55,&r));
  Load impossible=l;impossible.offset=200;
  assert(!make_record(source.data(),source.size(),&impossible,1,rip+2,257,55,&r));
  Load overlapping[2]{l,l};
  assert(!make_record(source.data(),source.size(),overlapping,2,rip+2,257,55,&r));
  source[0x25]=0x0F;source[0x26]=0x05;
  assert(!make_record(source.data(),source.size(),&l,1,rip+2,257,55,&r));
  assert(exact_service_process("com.r4.carxpc:r3d3_probe",sizeof("com.r4.carxpc:r3d3_probe")-1));
  assert(!exact_service_process("com.r4.carxpc",sizeof("com.r4.carxpc")-1));
  assert(!exact_service_process("com.r4.carxpc:r3d3_probe_fake",sizeof("com.r4.carxpc:r3d3_probe_fake")-1));
  std::cout << "R3D3_WITNESS_NEGATIVE_CONTROLS_PASS" << std::endl;
}
