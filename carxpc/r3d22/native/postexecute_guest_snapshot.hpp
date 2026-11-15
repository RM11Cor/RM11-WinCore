// SPDX-License-Identifier: MIT
// R3D22: guest CPU-state snapshot *after* FEX ExecuteThread returns.
// This diagnostic is read-only. No guest memory dereference, no restart,
// no instruction execution, and NO assertion that state.rip is a precise
// faulting instruction. The FEX frame may hold a stale RIP after JIT exit.
#pragma once
#include <cstdint>
#include <cstddef>
namespace carx_r3d22 {
struct ReturnSnapshot {
  uint64_t stateRip{};
  uint64_t rax{},rsp{},rbp{},rdi{},rsi{},rdx{};
  uint64_t fsBase{},gsBase{};
  uint8_t synchronousSignal{},trapNo{},siCode{};
  uint16_t errCode{};
  bool faultToTopAndGeneratedException{};
};
template<class FexFrame>
inline ReturnSnapshot capture_readonly_postexecute(const FexFrame& frame,
                  size_t raxIndex,size_t rspIndex,size_t rbpIndex,
                  size_t rdiIndex,size_t rsiIndex,size_t rdxIndex) noexcept {
  ReturnSnapshot r{};
  const auto& s=frame.State;
  r.stateRip=s.rip;
  r.rax=s.gregs[raxIndex];
  r.rsp=s.gregs[rspIndex];
  r.rbp=s.gregs[rbpIndex];
  r.rdi=s.gregs[rdiIndex];
  r.rsi=s.gregs[rsiIndex];
  r.rdx=s.gregs[rdxIndex];
  r.fsBase=s.fs_cached;
  r.gsBase=s.gs_cached;
  const auto& fault=frame.SynchronousFaultData;
  r.synchronousSignal=fault.Signal;
  r.trapNo=fault.TrapNo;
  r.siCode=fault.si_code;
  r.errCode=fault.err_code;
  r.faultToTopAndGeneratedException=fault.FaultToTopAndGeneratedException;
  return r;
}
inline bool coherent_register_snapshot(const ReturnSnapshot& snap) noexcept {
  return snap.rsp!=0 && snap.fsBase!=0 &&
         snap.fsBase<=0x00007FFFFFFFFFFFULL;
}
} // namespace carx_r3d22
