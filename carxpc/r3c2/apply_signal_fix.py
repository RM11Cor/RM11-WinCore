#!/usr/bin/env python3
"""R3-C2: precise Android/Bionic FEX SIGBUS signed PC-delta contract fix.

Only the CarX R3-C2 source worktree is patched; never mutate historical KERNIX.
The upstream FEX HandleUnalignedAccess contract explicitly returns:
  0   - JIT LDAR -> LDR plus DMB_LD; retry at same native PC
  -4   - JIT STLR -> STR plus preceding barrier; rewind native PC by 4
  +4   - successfully emulate one instruction and advance
The R3-C Android handler incorrectly treated zero as a failure and used an
unsigned overflow check that wrongly rejected -4. Both became _exit(183).
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: apply_signal_fix.py <path-to-original-KERNIX-Android-sigbus-header>")
p = Path(sys.argv[1])
s = p.read_text()
needle = """    if(!recovered.has_value() || !*recovered ||
       *recovered>128 || ((*recovered)&3U) ||
       pc>std::numeric_limits<uintptr_t>::max()-*recovered)
      ::_exit(183);
    uc->uc_mcontext.pc=pc+*recovered;"""
replacement = """    // Upstream FEX HandleUnalignedAccess returns a SIGNED native PC delta:
    //   0 = patched LDAR/LDAPR to LDR and barrier: RETRY SAME PC;
    //  -4 = patched STLR to STR: REWIND one AArch64 instruction;
    //   4 = emulated instruction: skip it.
    // A value of 0 is a valid successful optional result; unlike nullopt.
    // Never replace this with an unbounded skip or disable x86 TSO.
    if(!recovered.has_value()){
      static constexpr char msg[] =
        "KERNIX_G0_ANDROID_FEX_SIGBUS_UPSTREAM_NULL_RESULT_REJECT\\n";
      (void)::write(STDERR_FILENO,msg,sizeof(msg)-1);
      ::_exit(183);
    }
    const int32_t delta=*recovered;
    if(delta < -4 || delta > 128 || (delta & 3)){
      static constexpr char msg[] =
        "KERNIX_G0_ANDROID_FEX_SIGBUS_INVALID_SIGNED_DELTA_REJECT\\n";
      (void)::write(STDERR_FILENO,msg,sizeof(msg)-1);
      ::_exit(183);
    }
    uintptr_t resumedPC{};
    if(delta < 0){
      const uintptr_t rewind=static_cast<uintptr_t>(
        -static_cast<int64_t>(delta));
      if(pc < rewind)::_exit(183);
      resumedPC=pc-rewind;
    } else {
      const uintptr_t forward=static_cast<uintptr_t>(delta);
      if(pc > std::numeric_limits<uintptr_t>::max()-forward)
        ::_exit(183);
      resumedPC=pc+forward;
    }
    // Preserve native ARM64 4-byte instruction alignment and JIT ownership.
    // For -4 the adjacent barrier is emitted by FEX itself.
    if(resumedPC&3U)::_exit(183);
    uc->uc_mcontext.pc=resumedPC;
    if(self->handledCount_==0 && delta==0){
      static constexpr char msg[] =
        "KERNIX_G0_ANDROID_BIONIC_UPSTREAM_FEX_SIGBUS_SIGNED_DELTA_0_RETRY_SAME_JIT_PC\\n";
      (void)::write(STDERR_FILENO,msg,sizeof(msg)-1);
    } else if(self->handledCount_==0 && delta==-4){
      static constexpr char msg[] =
        "KERNIX_G0_ANDROID_BIONIC_UPSTREAM_FEX_SIGBUS_SIGNED_DELTA_NEG4_REWIND_DMB\\n";
      (void)::write(STDERR_FILENO,msg,sizeof(msg)-1);
    }"""
assert s.count(needle) == 1, f"Expected exactly one known R3C SIGBUS handler; got {s.count(needle)}"
assert "HandleUnalignedAccess(" in s
assert "kMaxHandledBusFaults=4096" in s
assert "IsAddressInCodeBuffer(self->guestThread_,pc)" in s
assert "CONFIG_TSOENABLED" not in replacement
result=s.replace(needle,replacement)
assert "|| !*recovered ||" not in result
assert "uc->uc_mcontext.pc=resumedPC" in result
p.write_text(result)
print("CARX_R3C2_SOURCE_FIXED: upstream signed returns 0/-4/+4 preserved; JIT ownership and fault budget unchanged")
