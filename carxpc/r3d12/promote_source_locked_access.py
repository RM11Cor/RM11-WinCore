#!/usr/bin/env python3
"""R3D12: bounded 07F continuation to third real original ld.so syscall.

Requires: successful source-pinned R3D11 code promotion.
Retains 07D/07E modes unchanged. Mode2 only:
  brk(0) => query reserved private guest heap (R3D11)
  access("/etc/ld.so.preload",R_OK) => -ENOENT only if the rootfs file
  is provably missing AND the pathname matches pinned GNU ld.so PT_LOAD bytes.
  The third genuine x86 syscall is witnessed (56-byte record) then exit 99.
Absolutely no generic host syscall forwarding or fake success path.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_source_locked_access.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
native=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java"
service=java/"R3D4ProbeService.java"
main=java/"MainActivity.java"
gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(p.is_file() for p in (native,act,service,main,gradle,store))
def one(s,old,new):
    n=s.count(old)
    assert n==1,("R3D12_SOURCE_ANCHOR_MISMATCH",old[:130],n)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+38\b","versionCode 39",s)
assert n==1,"R3D12_EXPECTS_SIGNED_R3D11_V38"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.39-r3d12-source-locked-access-third-syscall'",s)
assert n==1
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D11 — اختبار 07D + syscall الثاني من GNU",
        "10 | R3D12 — اختبار 07F للاستدعاء الثالث GNU")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D9_07D_Diagnostics_"',
        '"CarX_PC_R3D12_07F_Diagnostics_"')
store.write_text(s)

s=native.read_text()
s=one(s,
'''#include "carxpc/r3d3/native/r3d3_first_syscall_witness.hpp"''',
'''#include "carxpc/r3d3/native/r3d3_first_syscall_witness.hpp"
#include "carxpc/r3d12/native/source_guest_path.hpp"''')
s=one(s,
'''      Loads[Count++] = carx_r3d3::Load{LDSO_BIAS,seg.va,seg.fileOff,
                                        seg.fileSize,bool(seg.permission&PROT_EXEC)};''',
'''      Loads[Count++] = carx_r3d3::Load{LDSO_BIAS,seg.va,seg.fileOff,
                                        seg.fileSize,bool(seg.permission&PROT_EXEC)};
      ReadableLoads[ReadableCount++] = carx_r3d12::ReadableLoad{
          LDSO_BIAS,seg.va,seg.fileOff,seg.fileSize,
          bool(seg.permission&PROT_READ)};''')
s=one(s,
'''  uint64_t Nonce;
  uint64_t BRKBase;''',
'''  uint64_t Nonce;
  std::array<carx_r3d12::ReadableLoad,96> ReadableLoads{};
  size_t ReadableCount{0};
  uint64_t BRKBase;''')
s=one(s,'''    if (Mode!=1) ::_exit(98);''',
        '''    if (Mode!=1 && Mode!=2) ::_exit(98);''')
s=one(s,
'''      carx_r3d6::note("N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL");
      ::_exit(91);
    }
    ::_exit(98);''',
'''      carx_r3d6::note("N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL");
      if(Mode==1) ::_exit(91);
      if(Mode!=2) ::_exit(98);
      if(record.guest_syscall_number!=21) {
        carx_r3d6::note("E_R3D12_SECOND_NOT_ACCESS");
        ::_exit(104);
      }
      const uint64_t pathPtr=state.gregs[FEXCore::X86State::REG_RDI];
      const uint64_t modeFlags=state.gregs[FEXCore::X86State::REG_RSI];
      static constexpr char kPreload[]="/etc/ld.so.preload";
      if(modeFlags!=4) {
        carx_r3d6::note("E_R3D12_ACCESS_MODE_NOT_R_OK");
        ::_exit(105);
      }
      if(!carx_r3d12::source_guest_path_equals(
           Source,SourceLen,ReadableLoads.data(),ReadableCount,pathPtr,
           kPreload)) {
        carx_r3d6::note("E_R3D12_PATH_NOT_SOURCE_LOCKED_PRELOAD");
        ::_exit(106);
      }
      // Java checked the guest-rootfs preload absence before execution.
      // Never inspect an arbitrary native host filesystem path here.
      // Linux x86-64 syscall ABI returns -errno in RAX, advances past 0F05.
      state.gregs[FEXCore::X86State::REG_RAX]=
          static_cast<uint64_t>(-static_cast<int64_t>(ENOENT));
      if(record.opcode_guest_rip>UINT64_MAX-2)::_exit(107);
      state.rip=record.opcode_guest_rip+2;
      Seen=2;
      carx_r3d6::note("N16_ACCESS_PRELOAD_SOURCE_MATCHED_ENOENT");
      return;
    }
    if(Seen==2) {
      if(Mode!=2)::_exit(108);
      carx_r3d6::note("N17_THIRD_X86_SYSCALL_CALLBACK");
      char phase[100]{};
      std::snprintf(phase,sizeof(phase),"N17_THIRD_SYSCALL_NR_%llu",
          static_cast<unsigned long long>(record.guest_syscall_number));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N17_THIRD_ARG0_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_RDI]));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N17_THIRD_ARG1_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_RSI]));
      carx_r3d6::note(phase);
      std::snprintf(phase,sizeof(phase),"N17_THIRD_ARG2_%016llX",
          static_cast<unsigned long long>(
            state.gregs[FEXCore::X86State::REG_RDX]));
      carx_r3d6::note(phase);
      carx_r3d6::note("N18_THIRD_SOURCE_LOCKED_LDSO_SYSCALL");
      ::_exit(99);
    }
    ::_exit(98);''')
s=one(s,"if(mode==1 && !brkHeap.init(reason))return false;",
        "if(mode!=0 && !brkHeap.init(reason))return false;")
s=one(s,'''     (probeMode!=0 && probeMode!=1))''',
        '''     (probeMode!=0 && probeMode!=1 && probeMode!=2))''')
assert all(t in s for t in (
    "N16_ACCESS_PRELOAD_SOURCE_MATCHED_ENOENT",
    "N17_THIRD_X86_SYSCALL_CALLBACK",
    "N18_THIRD_SOURCE_LOCKED_LDSO_SYSCALL",
    "source_guest_path_equals",
    "N15_SECOND_SOURCE_LOCKED_LDSO_SYSCALL",
    "N9B_FEX_CALLRET_PREEXEC_VALIDATED",
    "context->ExecuteThread(thread)",
    "carx_r3d3::make_record("))
native.write_text(s)

s=service.read_text()
s=one(s,'''        if(probeMode!=0 && probeMode!=1){''',
        '''        if(probeMode!=0 && probeMode!=1 && probeMode!=2){''')
s=one(s,
'''                phase("J3_ROOTFS_PRESENT");''',
'''                phase("J3_ROOTFS_PRESENT");
                if(probeMode==2) {
                    Path etc = root.resolve("etc");
                    Path preload = etc.resolve("ld.so.preload");
                    if(Files.isSymbolicLink(etc) ||
                       Files.isSymbolicLink(preload) ||
                       !Files.notExists(preload,LinkOption.NOFOLLOW_LINKS)) {
                        phase("E_R3D12_PRELOAD_NOT_PROVEN_ABSENT");
                        return;
                    }
                    phase("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS");
                }''')
service.write_text(s)

s=act.read_text()
s=one(s,'''    private Button run07e;''',
        '''    private Button run07e;
    private Button run07f;''')
s=one(s,'''        layout.addView(run07e);''',
'''        layout.addView(run07e);
        run07f = new Button(this);
        run07f.setText("تشغيل اختبار 07F — الاستدعاء الثالث بعد access");
        layout.addView(run07f);''')
s=one(s,'''        run07e.setOnClickListener(v -> startProbe(1));''',
        '''        run07e.setOnClickListener(v -> startProbe(1));
        run07f.setOnClickListener(v -> startProbe(2));''')
s=one(s,'''if(probeMode!=0 && probeMode!=1)return;''',
        '''if(probeMode!=0 && probeMode!=1 && probeMode!=2)return;''')
s=one(s,'''        run07e.setEnabled(false);''',
        '''        run07e.setEnabled(false);
        run07f.setEnabled(false);''')
s=s.replace("run07e.setEnabled(true);",
            "run07e.setEnabled(true);run07f.setEnabled(true);")
s=one(s,
'''            report.put("schema",currentProbeMode==1 ?
                "r4.carx.r3d11.second-original-ldso-syscall.v1" :
                "r4.carx.r3d9.first-syscall-native-tombstone.v1");''',
'''            report.put("schema",currentProbeMode==2 ?
                "r4.carx.r3d12.third-original-ldso-syscall.v1" :
                currentProbeMode==1 ?
                "r4.carx.r3d11.second-original-ldso-syscall.v1" :
                "r4.carx.r3d9.first-syscall-native-tombstone.v1");''')
s=one(s,
'''            report.put("stage",currentProbeMode==1 ?
                "07E_LDSO_SECOND_FEX_SYSCALL_AFTER_BRK0" :
                "07D_WINE_LDSO_FIRST_FEX_SYSCALL");''',
'''            report.put("stage",currentProbeMode==2 ?
                "07F_LDSO_THIRD_SYSCALL_AFTER_ACCESS_PRELOAD" :
                currentProbeMode==1 ?
                "07E_LDSO_SECOND_FEX_SYSCALL_AFTER_BRK0" :
                "07D_WINE_LDSO_FIRST_FEX_SYSCALL");''')
s=one(s,
'''            report.put("probe_mode",currentProbeMode==1 ?
                "07E_BRK0_CONTINUE_ONE" : "07D_FIRST_ONLY");''',
'''            report.put("probe_mode",currentProbeMode==2 ?
                "07F_SOURCE_LOCKED_ACCESS_PRELOAD" :
                currentProbeMode==1 ?
                "07E_BRK0_CONTINUE_ONE" : "07D_FIRST_ONLY");''')
s=one(s,"                currentProbeMode==1);",
        "                currentProbeMode!=0);")
s=one(s,
'''                if (data.length==(currentProbeMode==1?112:56)) {''',
'''                if (data.length==(currentProbeMode==2?168:
                                   currentProbeMode==1?112:56)) {''')
s=one(s,'''                        if(currentProbeMode==1) {''',
        '''                        if(currentProbeMode!=0) {''')
s=one(s,
'''                                report.put("second_rip_interpretation",interpretation2);
                            }
                        }''',
'''                                report.put("second_rip_interpretation",interpretation2);
                                if(currentProbeMode==2) {
                                    int magic3=bb.getInt(),version3=bb.getInt();
                                    long nonce3=bb.getLong(),syscall3=bb.getLong(),
                                         opcode3=bb.getLong(),callback3=bb.getLong(),
                                         offset3=bb.getLong();
                                    int interpretation3=bb.getInt(),reserved3=bb.getInt();
                                    boolean good3=magic3==0x33443352 &&
                                        version3==2 && nonce3==expectedNonce &&
                                        syscall2==21 && syscall3<=0xFFFFFFFFL &&
                                        opcode3>=LOADER_BIAS &&
                                        opcode3-LOADER_BIAS<0x1000000L &&
                                        offset3<0x200000L && reserved3==0 &&
                                        ((interpretation3==1 && callback3==opcode3) ||
                                         (interpretation3==2 && callback3==opcode3+2));
                                    if(!good3) state="REJECTED_INVALID_THIRD_WITNESS";
                                    else {
                                        state="OBSERVED_THIRD_SOURCE_LOCKED_X86_LDSO_SYSCALL_AFTER_ACCESS";
                                        report.put("access_target_source_locked",
                                            "/etc/ld.so.preload");
                                        report.put("access_mode",4);
                                        report.put("access_guest_result_errno","ENOENT");
                                        report.put("third_syscall_number",syscall3);
                                        report.put("third_syscall_opcode_rip",
                                            String.format(Locale.ROOT,
                                                "0x%016x",opcode3));
                                        report.put("third_callback_rip",
                                            String.format(Locale.ROOT,
                                                "0x%016x",callback3));
                                        report.put("third_source_ldso_file_offset",offset3);
                                        report.put("third_rip_interpretation",interpretation3);
                                    }
                                }
                            }
                        }''')
s=one(s,
'''            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''',
'''            if(currentProbeMode==2 &&
               state.startsWith("OBSERVED_THIRD") &&
               !(phaseArray.toString().contains("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS") &&
                 phaseArray.toString().contains("N16_ACCESS_PRELOAD_SOURCE_MATCHED_ENOENT") &&
                 phaseArray.toString().contains("N17_THIRD_X86_SYSCALL_CALLBACK") &&
                 phaseArray.toString().contains("N18_THIRD_SOURCE_LOCKED_LDSO_SYSCALL"))) {
                state="REJECTED_MISSING_R3D12_SOURCE_LOCKED_PHASES";
            }
            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''')
s=one(s,'''            report.put("evidence_limit",currentProbeMode==1 ?''',
        '''            report.put("evidence_limit",currentProbeMode==2 ?
                "Three original source-locked GNU ld.so x86 syscalls, if observed. Bounded brk(0) and access(/etc/ld.so.preload,R_OK) absence responses are diagnostic guest shims, not a full Linux syscall layer. No Wine startup, PE, DXVK or game." :
                currentProbeMode==1 ?''')
s=one(s,
'''            headline.setText((currentProbeMode==1?"07E: ":"07D: ")+state+''',
'''            headline.setText((currentProbeMode==2?"07F: ":
                currentProbeMode==1?"07E: ":"07D: ")+state+''')
s=one(s,'''setTitle("CarX R3D9 | FEX / Wine 07D");''',
        '''setTitle("CarX R3D12 | FEX / Wine 07D-07F");''')
act.write_text(s)

assert all(t in act.read_text() for t in (
    "run07f","07F_SOURCE_LOCKED_ACCESS_PRELOAD",
    "OBSERVED_THIRD_SOURCE_LOCKED_X86_LDSO_SYSCALL_AFTER_ACCESS",
    "J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS",
    "saveReportToDownloads()","R3D9NativeCrashTrace.extract"))
print("R3D12_07D_07E_LEGACY_MODES_RETAINED")
print("R3D12_07F_SOURCE_PINNED_PRELOAD_READ_ONLY_ACCESS_THIRD_SYSCALL_PATCH_PASS")
print("R3D12_NO_LINUX_FULL_EMULATION_NO_WINE_OR_CARX_BOOT_CLAIM")
