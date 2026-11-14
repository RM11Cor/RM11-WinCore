#!/usr/bin/env python3
"""R3D11: opt-in bounded GNU ld.so second syscall after source-locked brk(0).

Stage 07D retained unchanged when mode=0. Mode=1:
  1. Capture source-verified first x86 syscall in FEX (fixed 56-byte R3D3 witness)
  2. Require syscall 12=brk and x86 arg0 RDI=0 (query only)
  3. Respond with address of a privately reserved guest 8MiB PROT_NONE region.
  4. Explicitly advance guest RIP past source-authenticated 0F 05.
  5. Capture the *next* original ld.so syscall in a second 56-byte R3D3 witness
     and exit 91, with no forwarding of guest syscalls to Android Bionic.

This is a diagnostic adapter for brk(0), NOT full Linux/Wine support.
"""
from pathlib import Path
import re,sys

if len(sys.argv)!=2:raise SystemExit("usage: promote_second_ldso_syscall.py /tmp/carxpc")
base=Path(sys.argv[1])
java=base/"app/src/main/java/com/r4/carxpc"
native=base/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java"
service=java/"R3D4ProbeService.java"
main=java/"MainActivity.java"
gradle=base/"app/build.gradle"
assert all(x.is_file() for x in (native,act,service,main,gradle))

def one(s,old,new):
    n=s.count(old)
    assert n==1,("R3D11_UNEXPECTED_SOURCE_ANCHOR",old[:140],n)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+37\b","versionCode 38",s)
assert n==1,"R3D11_REQUIRES_VERSION37"
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.38-r3d11-second-ldso-syscall'",s)
assert n==1
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D10 — إصلاح CallRet Stack داخل FEX 07D",
   "10 | R3D11 — اختبار 07D + syscall الثاني من GNU")
main.write_text(s)

s=native.read_text()
s=one(s,
'''                      int traceFd,uint64_t nonce)
    : WineBase(w),LdsoBase(l),WineLength(wineLen),LdsoLength(ldsoLen),
      Source(source.data()),SourceLen(source.size()),Fd(traceFd),Nonce(nonce) {''',
'''                      int traceFd,uint64_t nonce,uint64_t brkBase,int mode)
    : WineBase(w),LdsoBase(l),WineLength(wineLen),LdsoLength(ldsoLen),
      Source(source.data()),SourceLen(source.size()),Fd(traceFd),Nonce(nonce),
      BRKBase(brkBase),Mode(mode) {''')
s=one(s,
'''    carx_r3d6::note("N11_X86_SYSCALL_CALLBACK_ENTER");
    const auto& state=frame->State;''',
'''    carx_r3d6::note("N11_X86_SYSCALL_CALLBACK_ENTER");
    auto& state=frame->State;''')
s=one(s,
'''    if (n!=ssize_t(sizeof(record)) || ::fsync(Fd)!=0) ::_exit(94);
    ::_exit(90);''',
'''    if (n!=ssize_t(sizeof(record)) || ::fsync(Fd)!=0) ::_exit(94);
    if (Mode==0) ::_exit(90);  // Original 07D remains byte-identical.
    if (Mode!=1) ::_exit(98);
    if (Seen==0) {
      if (record.guest_syscall_number!=12) {
        carx_r3d6::note("E_R3D11_FIRST_SYSCALL_NOT_BRK");
        ::_exit(95);
      }
      const uint64_t arg0=state.gregs[FEXCore::X86State::REG_RDI];
      char phase[100]{};
      std::snprintf(phase,sizeof(phase),"N13_FIRST_BRK_RDI_%016llX",
        static_cast<unsigned long long>(arg0));
      carx_r3d6::note(phase);
      if(arg0!=0){
        carx_r3d6::note("E_R3D11_BRK_NONZERO_UNSUPPORTED");
        ::_exit(96);
      }
      if(!BRKBase || (BRKBase&4095)!=0 ||
         record.opcode_guest_rip > UINT64_MAX-2){
        carx_r3d6::note("E_R3D11_BRK_HEAP_OR_RIP_INVALID");
        ::_exit(97);
      }
      // Source-verified 0F 05; the callback's captured RIP is at the opcode
      // or 2 bytes past it. Follow upstream FEX syscall-return convention.
      state.gregs[FEXCore::X86State::REG_RAX]=BRKBase;
      state.rip=record.opcode_guest_rip+2;
      Seen=1;
      carx_r3d6::note("N13_BRK_ZERO_QUERY_EMULATED");
      return; // Continue original x86 code in FEX; no host syscall passthrough.
    }
    if (Seen==1) {
      carx_r3d6::note("N14_SECOND_X86_SYSCALL_CALLBACK");
      char phase[100]{};
      std::snprintf(phase,sizeof(phase),"N14_SECOND_SYSCALL_NR_%llu",
        static_cast<unsigned long long>(record.guest_syscall_number));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N14_SECOND_ARG0_%016llX",
        static_cast<unsigned long long>(
          state.gregs[FEXCore::X86State::REG_RDI]));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N14_SECOND_ARG1_%016llX",
        static_cast<unsigned long long>(
          state.gregs[FEXCore::X86State::REG_RSI]));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N14_SECOND_ARG2_%016llX",
        static_cast<unsigned long long>(
          state.gregs[FEXCore::X86State::REG_RDX]));
      carx_r3d6::note(phase);
      carx_r3d6::note("N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL");
      ::_exit(91);
    }
    ::_exit(98);''')
s=one(s,
'''  uint64_t Nonce;
};''',
'''  uint64_t Nonce;
  uint64_t BRKBase;
  int Mode{0};
  int Seen{0};
};''')
s=one(s,
'''bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,''',
'''// Reserve guest virtual address space for query-only Linux brk(0).
// This probe does not allocate/commit guest heap pages or emulate brk growth.
struct R3D11GuestBrkReservation {
  void* p{MAP_FAILED};
  static constexpr size_t kReserve=8*1024*1024;
  bool init(std::string& error) {
    p=::mmap(nullptr,kReserve,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) {
      error="R3D11_GUEST_BRK_RESERVE_FAILED_"+std::to_string(errno);
      return false;
    }
    if ((reinterpret_cast<uintptr_t>(p)&4095)!=0) {
      error="R3D11_GUEST_BRK_UNALIGNED";
      return false;
    }
    return true;
  }
  uint64_t base() const {
    return p==MAP_FAILED?0:reinterpret_cast<uintptr_t>(p);
  }
  ~R3D11GuestBrkReservation(){
    if(p!=MAP_FAILED)::munmap(p,kReserve);
  }
};
bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,''')
s,n=re.subn(
    r"(bool createFEXContextBoundToWine\([\s\S]{0,700}?int traceFd,uint64_t nonce)(,\s*std::string& reason\) \{)",
    r"\1,int mode\2",s,count=1)
assert n==1,"R3D11_FEX_CONTEXT_SIGNATURE_NOT_FOUND"
s=one(s,
'''  GuardedFEXCallRetStack callretGuard{};
  auto context=FEXCore::Context::Context::CreateNewContext(host);''',
'''  GuardedFEXCallRetStack callretGuard{};
  R3D11GuestBrkReservation brkHeap{};
  if(mode==1 && !brkHeap.init(reason))return false;
  auto context=FEXCore::Context::Context::CreateNewContext(host);''')
s=one(s,
'''    originalLdso,ldso,traceFd,nonce};''',
'''    originalLdso,ldso,traceFd,nonce,brkHeap.base(),mode};''')
s,n=re.subn(r"(uint64_t rsp,int traceFd,uint64_t nonce)(,\s*std::string &message\)\{)",
            r"\1,int mode\2",s,count=1)
assert n==1,"R3D11_RUN_SIGNATURE_MISSING"
s=one(s,'we,le,ldso,traceFd,nonce,message)){',
        'we,le,ldso,traceFd,nonce,mode,message)){')
s=one(s,'''  jlong nonce,jint traceFd,jint progressFd){''',
        '''  jlong nonce,jint traceFd,jint progressFd,jint probeMode){''')
s=one(s,'''  if(nonce<=0 || traceFd<0 || progressFd<0)''',
        '''  if(nonce<=0 || traceFd<0 || progressFd<0 ||
     (probeMode!=0 && probeMode!=1))''')
s=one(s,'''                              int(traceFd),uint64_t(nonce),msg);''',
        '''                              int(traceFd),uint64_t(nonce),int(probeMode),msg);''')
assert all(t in s for t in (
 "N13_BRK_ZERO_QUERY_EMULATED","N14_SECOND_X86_SYSCALL_CALLBACK",
 "N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL","N9B_FEX_CALLRET_PREEXEC_VALIDATED",
 "carx_r3d3::make_record(","::mmap(nullptr,kReserve,PROT_NONE",
 "state.gregs[FEXCore::X86State::REG_RAX]=BRKBase;",
 "state.rip=record.opcode_guest_rip+2;","context->ExecuteThread(thread)"))
assert '::_exit(90);' in s and '::_exit(91);' in s
native.write_text(s)

s=service.read_text()
s=one(s,'''long sessionNonce, int traceFd, int progressFd);''',
        '''long sessionNonce, int traceFd, int progressFd, int probeMode);''')
s=one(s,
'''        // A fresh phase log is required to tie events to this one launch.''',
'''        final int probeMode=request==null?0:
            request.getIntExtra("r3d11_stage_mode",0);
        if(probeMode!=0 && probeMode!=1){
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        // A fresh phase log is required to tie events to this one launch.''')
s=one(s,
'''                    plan.stackRSP, nonce, rawFd, progressFd);''',
'''                    plan.stackRSP, nonce, rawFd, progressFd, probeMode);''')
service.write_text(s)

s=act.read_text()
s=one(s,'''    private Button run;''',
        '''    private Button run;
    private Button run07e;
    private int currentProbeMode=0;''')
s=one(s,'''        layout.addView(run);''',
'''        layout.addView(run);
        run07e = new Button(this);
        run07e.setText("تشغيل اختبار 07E — syscall الثاني بعد brk(0)");
        layout.addView(run07e);''')
s=one(s,'''        run.setOnClickListener(v -> startProbe());''',
'''        run.setOnClickListener(v -> startProbe());
        run07e.setOnClickListener(v -> startProbe(1));''')
s=one(s,'''    private void startProbe() {
        if (running) return;
        running = true; run.setEnabled(false);''',
'''    private void startProbe() { startProbe(0); }
    private void startProbe(int probeMode) {
        if (running) return;
        if(probeMode!=0 && probeMode!=1)return;
        currentProbeMode=probeMode;
        running = true; run.setEnabled(false);
        run07e.setEnabled(false);''')
s=one(s,
'''            intent.putExtra("r3d4_nonce", sessionNonce);''',
'''            intent.putExtra("r3d4_nonce", sessionNonce);
            intent.putExtra("r3d11_stage_mode", currentProbeMode);''')
# Both early-exit error branches and normal end must re-enable new button.
s=s.replace("running = false; run.setEnabled(true);",
            "running = false; run.setEnabled(true); run07e.setEnabled(true);")
s=s.replace("running = false;run.setEnabled(true);",
            "running = false;run.setEnabled(true);run07e.setEnabled(true);")
assert "run07e.setEnabled(true)" in s

s=one(s,
'''            report.put("schema","r4.carx.r3d9.first-syscall-native-tombstone.v1");
            report.put("stage","07D_WINE_LDSO_FIRST_FEX_SYSCALL");''',
'''            report.put("schema",currentProbeMode==1 ?
                "r4.carx.r3d11.second-original-ldso-syscall.v1" :
                "r4.carx.r3d9.first-syscall-native-tombstone.v1");
            report.put("stage",currentProbeMode==1 ?
                "07E_LDSO_SECOND_FEX_SYSCALL_AFTER_BRK0" :
                "07D_WINE_LDSO_FIRST_FEX_SYSCALL");
            report.put("probe_mode",currentProbeMode==1 ?
                "07E_BRK0_CONTINUE_ONE" : "07D_FIRST_ONLY");
            report.put("brk0_guest_response_is_diagnostic_shim",
                currentProbeMode==1);
            report.put("unknown_x86_syscalls_forwarded_to_host",false);''')
s=one(s,
'''                if (data.length==56) {''',
'''                if (data.length==(currentProbeMode==1?112:56)) {''')
old='''                        report.put("rip_interpretation",interpretation);'''
new='''                        report.put("rip_interpretation",interpretation);
                        if(currentProbeMode==1) {
                            int magic2=bb.getInt(),version2=bb.getInt();
                            long nonce2=bb.getLong(),syscall2=bb.getLong(),
                                 opcode2=bb.getLong(),callback2=bb.getLong(),
                                 offset2=bb.getLong();
                            int interpretation2=bb.getInt(),reserved2=bb.getInt();
                            boolean good2=magic2==0x33443352 && version2==2 &&
                                nonce2==expectedNonce && syscall==12 &&
                                syscall2<=0xFFFFFFFFL &&
                                opcode2>=LOADER_BIAS &&
                                opcode2-LOADER_BIAS<0x1000000L &&
                                offset2<0x200000L && reserved2==0 &&
                                ((interpretation2==1 && callback2==opcode2) ||
                                 (interpretation2==2 && callback2==opcode2+2));
                            if(!good2) {
                                state="REJECTED_INVALID_SECOND_WITNESS";
                            } else {
                                state="OBSERVED_SECOND_SOURCE_LOCKED_X86_LDSO_SYSCALL_AFTER_BRK0";
                                report.put("first_syscall_number",syscall);
                                report.put("first_brk_zero_query_expected",true);
                                report.put("second_syscall_number",syscall2);
                                report.put("second_syscall_opcode_rip",
                                    String.format(Locale.ROOT,"0x%016x",opcode2));
                                report.put("second_callback_rip",
                                    String.format(Locale.ROOT,"0x%016x",callback2));
                                report.put("second_source_ldso_file_offset",offset2);
                                report.put("second_rip_interpretation",interpretation2);
                            }
                        }'''
s=one(s,old,new)
s=one(s,
'''            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''',
'''            if (currentProbeMode==1 &&
                state.startsWith("OBSERVED_SECOND") &&
                !(phaseArray.toString().contains("N13_BRK_ZERO_QUERY_EMULATED") &&
                  phaseArray.toString().contains("N14_SECOND_X86_SYSCALL_CALLBACK") &&
                  phaseArray.toString().contains("N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL"))) {
                state="REJECTED_MISSING_BRK0_CONTINUATION_PHASES";
            }
            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''')
s=one(s,
'''            report.put("evidence_limit",
                "Only original GNU ld.so first x86 Linux syscall, if witnessed. Not Wine startup, PE, DXVK or gameplay.");''',
'''            report.put("evidence_limit",currentProbeMode==1 ?
                "Two source-locked x86 ld.so syscalls only if independently verified; brk(0) query uses diagnostic reserved guest address, not full Linux brk. Not Wine startup, PE, DXVK or gameplay." :
                "Only original GNU ld.so first x86 Linux syscall, if witnessed. Not Wine startup, PE, DXVK or gameplay.");''')
# Old 07D remains manually accessible, 07E labelled separately.
s=one(s,
'''            headline.setText("07D: "+state+" | آخر مرحلة: "+''',
'''            headline.setText((currentProbeMode==1?"07E: ":"07D: ")+state+
                " | آخر مرحلة: "+''')
act.write_text(s)

for tag in ("07E_BRK0_CONTINUE_ONE","N13_BRK_ZERO_QUERY_EMULATED",
 "OBSERVED_SECOND_SOURCE_LOCKED_X86_LDSO_SYSCALL_AFTER_BRK0",
 "R3D9NativeCrashTrace.extract","saveReportToDownloads()"):
    assert tag in act.read_text() or tag in native.read_text(),tag
print("R3D11_SOURCE_PINNED_BRK0_BOUND_2_SYSCALL_NATIVE_PROMOTION_PASS")
print("R3D11_07D_LEGACY_SINGLE_WITNESS_MODE_UNCHANGED")
print("R3D11_07E_NEW_TWO_ORIGINAL_LDSO_WITNESSES_NO_HOST_PASSTHROUGH")
