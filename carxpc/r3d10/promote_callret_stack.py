#!/usr/bin/env python3
"""R3D10: Fix the source-proven x25==0 CALLRET_SP crash in original FEX JIT.

Source evidence:
  FEX pinned 02e24ca5: Arm64Emitter.h REG_CALLRET_SP = x25.
  FEX pinned 02e24ca5: ThreadManager.cpp installs CallRetStackBase and
      CPUState.callret_sp after CTX->CreateThread().
  R3D9 device tombstone: stp x20,x0,[x25,#-16]! with x25=0,
      fault_address=0xfffffffffffffff0, PC=[anon:FEXMemJIT]+0x24.

Our direct CTX->CreateThread() skipped frontend-managed CallRetStack setup.
Allocate the same 4MiB call-ret stack with 4KiB guard pages on both sides,
and set the same default SP at base + (size/4), before ExecuteThread.
Do not change the original x86 loader, Wine, guest stack, syscall witness,
or set any synthesized success marker.
"""
from pathlib import Path
import re,sys

if len(sys.argv)!=2:
    raise SystemExit("usage: promote_callret_stack.py /tmp/carxpc")
root=Path(sys.argv[1])
gradle=root/"app/build.gradle"
main=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
native=root/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
assert all(p.is_file() for p in (gradle,main,native))

def once(s,old,new):
    count=s.count(old)
    assert count==1,("SOURCE_PINNED_ANCHOR_CHANGED",old[:90],count)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+36\b","versionCode 37",s)
assert n==1, "R3D10_EXPECTS_R3D9_VERSION36"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.37-r3d10-fex-callret-stack-init'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=once(s,"10 | R3D9 — استخراج انهيار Wine/FEX إلى JSON",
     "10 | R3D10 — إصلاح CallRet Stack داخل FEX 07D")
main.write_text(s)

s=native.read_text()
# The exact guest ABI and FEX source layout is deliberately retained.
s=once(s,
'''bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,''',
'''// x25 is REG_CALLRET_SP in FEX ARM64. Source-pinned Linux frontend
// ThreadManager allocates this 4MiB stack + 4KiB guard pages per thread.
// Context::CreateThread alone does not initialize it.
struct GuardedFEXCallRetStack {
  void* reservation{MAP_FAILED};
  size_t mappedLen{0};
  bool init(FEXCore::Core::InternalThreadState* thread, std::string& error) {
    if(!thread || !thread->CurrentFrame){
      error="CALLRET_THREAD_OR_FRAME_NULL";return false;
    }
    constexpr size_t sz=FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
    static_assert(sz==0x400000 && (sz%PAGE)==0,
                  "PINNED_FEX_CALLRET_STACK_SIZE_CHANGED");
    constexpr size_t total=sz+2*PAGE;
    void* p=::mmap(nullptr,total,PROT_NONE,
                   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED){
      error="CALLRET_MMAP_FAILED_"+std::to_string(errno);return false;
    }
    reservation=p;mappedLen=total;
    uint8_t* writable=static_cast<uint8_t*>(p)+PAGE;
    if(::mprotect(writable,sz,PROT_READ|PROT_WRITE)!=0){
      error="CALLRET_MPROTECT_FAILED_"+std::to_string(errno);return false;
    }
#ifdef MADV_NOHUGEPAGE
    (void)::madvise(writable,sz,MADV_NOHUGEPAGE);
#endif
    thread->CallRetStackBase=writable;
    const uintptr_t defaultSP=reinterpret_cast<uintptr_t>(writable)+sz/4;
    thread->CurrentFrame->State.callret_sp=defaultSP;
    if(!defaultSP || (defaultSP&15) ||
       defaultSP<reinterpret_cast<uintptr_t>(writable)+16 ||
       defaultSP>=reinterpret_cast<uintptr_t>(writable)+sz-16) {
      error="CALLRET_DEFAULT_SP_INVALID";return false;
    }
    return true;
  }
  ~GuardedFEXCallRetStack(){
    if(reservation!=MAP_FAILED && mappedLen!=0)
      ::munmap(reservation,mappedLen);
  }
  GuardedFEXCallRetStack()=default;
  GuardedFEXCallRetStack(const GuardedFEXCallRetStack&)=delete;
  GuardedFEXCallRetStack& operator=(const GuardedFEXCallRetStack&)=delete;
};
bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,''')

# Destructor order: guard is constructed before Context and will be
# unmapped only AFTER the FEX context exits/destructs. Native process
# isolation is still mandatory.
s=once(s,'''  auto context=FEXCore::Context::Context::CreateNewContext(host);''',
       '''  GuardedFEXCallRetStack callretGuard{};
  auto context=FEXCore::Context::Context::CreateNewContext(host);''')

# Place the allocation immediately after CreateThread and frame validation,
# before the 07D guest RIP/RSP setup and any ExecuteThread call.
old='''  auto& state=thread->CurrentFrame->State;'''
new='''  if(!callretGuard.init(thread,reason))return false;
  if(!thread->CallRetStackBase ||
     thread->CurrentFrame->State.callret_sp == 0){
    reason="CALLRET_STACK_NOT_BOUND";return false;
  }
  carx_r3d6::note("N9A_FEX_CALLRET_STACK_READY");
  auto& state=thread->CurrentFrame->State;'''
s=once(s,old,new)

# Prove the value cannot be lost between setup and ExecuteThread.
s=once(s,'''  carx_r3d6::note("N10_EXECUTE_THREAD_ENTER");
  context->ExecuteThread(thread);''',
'''  if(!thread->CallRetStackBase ||
     thread->CurrentFrame->State.callret_sp==0 ||
     thread->CurrentFrame->State.callret_sp !=
       reinterpret_cast<uintptr_t>(thread->CallRetStackBase)
         + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE/4){
    reason="CALLRET_PREEXEC_VERIFY_FAILED";return false;
  }
  carx_r3d6::note("N9B_FEX_CALLRET_PREEXEC_VALIDATED");
  carx_r3d6::note("N10_EXECUTE_THREAD_ENTER");
  context->ExecuteThread(thread);''')

assert '::mmap(nullptr,total,PROT_NONE' in s
assert 'thread->CurrentFrame->State.callret_sp=defaultSP;' in s
assert 'N9A_FEX_CALLRET_STACK_READY' in s
assert 'N9B_FEX_CALLRET_PREEXEC_VALIDATED' in s
assert 'N10_EXECUTE_THREAD_ENTER' in s
assert 'N11_X86_SYSCALL_CALLBACK_ENTER' in s
assert 'context->ExecuteThread(thread)' in s
assert 'carx_r3d3::make_record(' in s
assert 'R3D4ProbeService_nativeRun' in s
assert 'ExplicitNoWineExecutionSyscalls' not in s
native.write_text(s)
print("R3D10_SOURCE_PINNED_CALLRET_X25_INITIALIZATION_PATCH_PASS")
print("R3D10_REAL_FEX_GUARD_PAGES_4M_STACK_SAME_FRONTEND_DEFAULT_SP")
print("R3D10_NO_FAKE_SYSCALL_WITNESS_NO_GUEST_SHIM_NO_BOOT_CLAIM")
