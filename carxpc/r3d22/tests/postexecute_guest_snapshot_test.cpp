#include "carxpc/r3d22/native/postexecute_guest_snapshot.hpp"
#include <cassert>
#include <cstdio>
#include <cstdint>
struct MockFrame {
  struct StateType {
    uint64_t rip{}, gregs[16]{}, fs_cached{},gs_cached{};
  } State;
  struct FaultType {
    bool FaultToTopAndGeneratedException{};
    uint8_t Signal{},TrapNo{},si_code{};
    uint16_t err_code{};
  } SynchronousFaultData;
};
int main(){
  MockFrame f{};
  f.State.rip=0x4100015010ULL;
  f.State.gregs[0]=uint64_t(-38); // last rseq -ENOSYS
  f.State.gregs[1]=0x7000;
  f.State.gregs[2]=0x6000;
  f.State.gregs[3]=0x1111;
  f.State.gregs[4]=0x2222;
  f.State.gregs[5]=0x3333;
  f.State.fs_cached=0x770D766100ULL;
  f.State.gs_cached=0;
  f.SynchronousFaultData.Signal=11;
  f.SynchronousFaultData.TrapNo=14;
  f.SynchronousFaultData.si_code=1;
  f.SynchronousFaultData.err_code=4;
  f.SynchronousFaultData.FaultToTopAndGeneratedException=true;
  const auto s=carx_r3d22::capture_readonly_postexecute(f,0,1,2,3,4,5);
  assert(s.stateRip==f.State.rip);
  assert(s.rax==uint64_t(-38));
  assert(s.rsp==0x7000 && s.rbp==0x6000 && s.fsBase==0x770D766100ULL);
  assert(s.rdi==0x1111 && s.rsi==0x2222 && s.rdx==0x3333);
  assert(s.synchronousSignal==11 && s.trapNo==14 &&
         s.siCode==1 && s.errCode==4);
  assert(s.faultToTopAndGeneratedException);
  assert(carx_r3d22::coherent_register_snapshot(s));
  f.State.fs_cached=0;
  assert(!carx_r3d22::coherent_register_snapshot(
    carx_r3d22::capture_readonly_postexecute(f,0,1,2,3,4,5)));
  std::puts("R3D22_FEX_POSTEXECUTE_READONLY_CPUSTATE_AND_SYNC_FAULT_FIELDS_HOST_TEST_PASS");
}
