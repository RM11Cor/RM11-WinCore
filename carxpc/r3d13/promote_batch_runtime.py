#!/usr/bin/env python3
"""CarX R3D13: manually triggered, source-locked, bounded FEX guest syscall batch.

Legacy 07D, 07E, 07F modes stay untouched. New mode 3 records up to 32
genuine original GNU ld.so x86 syscalls in one 56B-per-event witness journal.
Only explicitly safe guest queries are continued:
 * brk(0) query -> owned reserved guest heap pointer, no commit/growth
 * access("/etc/ld.so.preload", R_OK), only after proving missing rootfs file
 * openat(AT_FDCWD,"/etc/ld.so.cache",O_CLOEXEC,0), only after proving missing
   rootfs file; return -ENOENT, never forward the guest FD to Android.
Unknown/unsupported modes STOP with phase reason and last source witness.
This does not bootstrap Wine, load PE or draw the game.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:
    raise SystemExit("usage: promote_batch_runtime.py /tmp/carxpc")
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
native=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
service=java/"R3D4ProbeService.java"
activity=java/"R3D4ProbeActivity.java"
main=java/"MainActivity.java"
gradle=app/"app/build.gradle"
store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (native,service,activity,main,gradle,store))
def one(s,old,new):
    c=s.count(old)
    assert c==1,("R3D13_SOURCE_BOUNDARY_CHANGED",old[:125],c)
    return s.replace(old,new,1)

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+39\b","versionCode 40",s)
assert n==1,"R3D13_REQUIRES_V39"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.40-r3d13-batched-ldso-syscall-diagnostics'",s)
assert n==1
gradle.write_text(s)

s=main.read_text()
s=one(s,"10 | R3D12 — اختبار 07F للاستدعاء الثالث GNU",
      "10 | R3D13 — فحص استدعاءات GNU المجمّع")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D12_07F_Diagnostics_"',
      '"CarX_PC_R3D13_Batch_Diagnostics_"')
store.write_text(s)

s=native.read_text()
s=one(s,'''#include "carxpc/r3d12/native/source_guest_path.hpp"''',
'''#include "carxpc/r3d12/native/source_guest_path.hpp"
#include "carxpc/r3d13/native/strict_batch_policy.hpp"''')
# This branch intentionally runs before all old mode 0/1/2 branches.
batch= r'''    if (Mode==3) {
      char msg[112]{};
      if(Seen>=carx_r3d13::kMaxWitnesses-1) {
        carx_r3d6::note("E_BATCH_WITNESS_CAP_32_REACHED");
        ::_exit(114);
      }
      const uint64_t number=record.guest_syscall_number;
      const uint64_t arg0=state.gregs[FEXCore::X86State::REG_RDI];
      const uint64_t arg1=state.gregs[FEXCore::X86State::REG_RSI];
      const uint64_t arg2=state.gregs[FEXCore::X86State::REG_RDX];
      std::snprintf(msg,sizeof(msg),"N21_BATCH_INDEX_%u",Seen);
      carx_r3d6::note(msg);
      std::snprintf(msg,sizeof(msg),"N21_BATCH_NR_%llu",
        static_cast<unsigned long long>(number));
      carx_r3d6::note(msg);
      std::snprintf(msg,sizeof(msg),"N21_BATCH_ARG0_%016llX",
        static_cast<unsigned long long>(arg0));
      carx_r3d6::note(msg);
      std::snprintf(msg,sizeof(msg),"N21_BATCH_ARG1_%016llX",
        static_cast<unsigned long long>(arg1));
      carx_r3d6::note(msg);
      std::snprintf(msg,sizeof(msg),"N21_BATCH_ARG2_%016llX",
        static_cast<unsigned long long>(arg2));
      carx_r3d6::note(msg);
      if (record.opcode_guest_rip>UINT64_MAX-2) {
        carx_r3d6::note("E_BATCH_INVALID_SYSCALL_RIP");
        ::_exit(116);
      }
      // The native callback is reached after a real source-verified x86 0F05.
      // These are guest-only responses, not Android host syscall forwarding.
      const uint64_t newRIP=record.opcode_guest_rip+2;
      if(carx_r3d13::is_safe_brk_zero_query(number,arg0) &&
         BRKBase && (BRKBase&4095)==0) {
        state.gregs[FEXCore::X86State::REG_RAX]=BRKBase;
        state.rip=newRIP;
        ++Seen;
        carx_r3d6::note("N22_BATCH_RETURN_BRK0_GUEST_RESERVATION");
        return;
      }
      static constexpr char kPreload[]="/etc/ld.so.preload";
      if(carx_r3d13::is_safe_preload_access_query(number,arg1) &&
         carx_r3d12::source_guest_path_equals(
           Source,SourceLen,ReadableLoads.data(),ReadableCount,arg0,
           kPreload)) {
        state.gregs[FEXCore::X86State::REG_RAX]=
          static_cast<uint64_t>(-static_cast<int64_t>(ENOENT));
        state.rip=newRIP;
        ++Seen;
        carx_r3d6::note("N22_BATCH_RETURN_ACCESS_PRELOAD_ENOENT");
        return;
      }
      static constexpr char kCache[]="/etc/ld.so.cache";
      const uint64_t dirfd=arg0;
      const uint64_t flags=arg2;
      const uint64_t mode=state.gregs[FEXCore::X86State::REG_R10];
      if(number==carx_r3d13::kOpenAt &&
         carx_r3d13::is_safe_missing_guest_cache_openat(dirfd,flags,mode) &&
         carx_r3d12::source_guest_path_equals(
           Source,SourceLen,ReadableLoads.data(),ReadableCount,arg1,
           kCache)) {
        state.gregs[FEXCore::X86State::REG_RAX]=
          static_cast<uint64_t>(-static_cast<int64_t>(ENOENT));
        state.rip=newRIP;
        ++Seen;
        carx_r3d6::note("N22_BATCH_RETURN_OPENAT_CACHE_ENOENT");
        return;
      }
      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",
        static_cast<unsigned long long>(number));
      carx_r3d6::note(msg);
      ::_exit(113);
    }
'''
s=one(s,'''    if (Mode==0) ::_exit(90);  // Original 07D remains byte-identical.''',
      batch+'''    if (Mode==0) ::_exit(90);  // Original 07D remains byte-identical.''')
s=one(s,'''     (probeMode!=0 && probeMode!=1 && probeMode!=2))''',
      '''     (probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3))''')
# Protect mode 3's guest brk reservation, same earlier safe behavior.
assert "if(mode!=0 && !brkHeap.init(reason))return false;" in s
assert "source_guest_path_equals" in s
assert "N22_BATCH_RETURN_OPENAT_CACHE_ENOENT" in s
assert "context->ExecuteThread(thread)" in s
assert "carx_r3d3::make_record(" in s
assert "::_exit(113);" in s
native.write_text(s)

s=service.read_text()
s=one(s,'''        if(probeMode!=0 && probeMode!=1 && probeMode!=2){''',
      '''        if(probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3){''')
s=one(s,'''                if(probeMode==2) {''',
      '''                if(probeMode==2 || probeMode==3) {''')
s=one(s,'''                    phase("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS");
                }''',
'''                    phase("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS");
                    if(probeMode==3) {
                        Path cache=etc.resolve("ld.so.cache");
                        if(Files.isSymbolicLink(cache) ||
                           !Files.notExists(cache,LinkOption.NOFOLLOW_LINKS)) {
                            phase("E_BATCH_CACHE_ABSENCE_NOT_PROVEN");
                            return;
                        }
                        phase("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS");
                    }
                }''')
service.write_text(s)

s=activity.read_text()
s=one(s,'''    private Button run07f;''',
      '''    private Button run07f;
    private Button runBatch;''')
s=one(s,'''        layout.addView(run07f);''',
'''        layout.addView(run07f);
        runBatch = new Button(this);
        runBatch.setText("تشغيل فحص الاستدعاءات المجمّع — JSON واحد");
        layout.addView(runBatch);''')
s=one(s,'''        run07f.setOnClickListener(v -> startProbe(2));''',
      '''        run07f.setOnClickListener(v -> startProbe(2));
        runBatch.setOnClickListener(v -> startProbe(3));''')
s=one(s,'''if(probeMode!=0 && probeMode!=1 && probeMode!=2)return;''',
      '''if(probeMode!=0 && probeMode!=1 && probeMode!=2 && probeMode!=3)return;''')
s=one(s,'''        run07f.setEnabled(false);''',
      '''        run07f.setEnabled(false);
        runBatch.setEnabled(false);''')
s=s.replace("run07f.setEnabled(true);",
            "run07f.setEnabled(true);runBatch.setEnabled(true);")
s=one(s,
'''            report.put("schema",currentProbeMode==2 ?''',
'''            report.put("schema",currentProbeMode==3 ?
                "r4.carx.r3d13.batched-original-ldso-syscalls.v1" :
                currentProbeMode==2 ?''')
s=one(s,
'''            report.put("stage",currentProbeMode==2 ?''',
'''            report.put("stage",currentProbeMode==3 ?
                "07G_BOUNDED_ORIGINAL_LDSO_SYSCALL_BATCH" :
                currentProbeMode==2 ?''')
s=one(s,
'''            report.put("probe_mode",currentProbeMode==2 ?''',
'''            report.put("probe_mode",currentProbeMode==3 ?
                "07G_BOUNDED_SOURCE_LOCKED_BATCH_32" :
                currentProbeMode==2 ?''')
s=one(s,
'''                if (data.length==(currentProbeMode==2?168:''',
'''                if (currentProbeMode!=3 &&
                    data.length==(currentProbeMode==2?168:''')
s=one(s,
'''            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''',
'''            if(currentProbeMode==3) {
                state=inspectBatchJournal(file,expectedNonce,report,
                    phaseArray,phaseSessionValid);
            }
            if (!phaseSessionValid && state.startsWith("OBSERVED")) {''')
s=one(s,'''                if (!lines.isEmpty() && lines.size() <= 48 &&''',
      '''                if (!lines.isEmpty() && lines.size() <= 512 &&''')
s=one(s,
'''            report.put("evidence_limit",currentProbeMode==2 ?''',
'''            report.put("evidence_limit",currentProbeMode==3 ?
                "Up to 32 individually source-verified original GNU ld.so syscalls in one process, with limited brk(0), missing preload access, missing cache openat responses. Unknown syscalls halt with evidence; not a full Linux or Wine runtime, Windows PE, DXVK or gameplay." :
                currentProbeMode==2 ?''')
s=one(s,
'''            headline.setText((currentProbeMode==2?"07F: ":''',
'''            headline.setText((currentProbeMode==3?"07G BATCH: ":
                currentProbeMode==2?"07F: ":''')
# For the batch, the 56-byte native source witness is still the ONLY proof
# per event; the phase strings alone are explicitly not an acceptance proof.
insert=r'''
    private static String inspectBatchJournal(
        File file,long expectedNonce,JSONObject report,
        JSONArray phases,boolean validSession) throws Exception {
        report.put("batch_max_witnesses",32);
        report.put("batch_direct_host_syscalls_forwarded",false);
        report.put("batch_guest_responses_are_bounded_diagnostic_shims",true);
        if(!validSession) return "BATCH_REJECTED_PHASE_NONCE_MISMATCH";
        if(!file.isFile()) return "BATCH_REJECTED_NO_WITNESS_FILE";
        final byte[] data=Files.readAllBytes(file.toPath());
        if(data.length==0 || data.length%56!=0 ||
           data.length>32*56) return "BATCH_REJECTED_WITNESS_LENGTH";
        final int count=data.length/56;
        ByteBuffer bb=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        JSONArray events=new JSONArray();
        for(int i=0;i<count;++i) {
            int magic=bb.getInt(),version=bb.getInt();
            long nonce=bb.getLong(),number=bb.getLong(),
                 opcode=bb.getLong(),callback=bb.getLong(),offset=bb.getLong();
            int interp=bb.getInt(),reserved=bb.getInt();
            boolean valid=magic==0x33443352 && version==2 &&
                nonce==expectedNonce && number<=0xFFFFFFFFL &&
                opcode>=LOADER_BIAS && opcode-LOADER_BIAS<0x1000000L &&
                offset<0x200000L && reserved==0 &&
                ((interp==1 && callback==opcode) ||
                 (interp==2 && callback==opcode+2));
            if(!valid) {
                report.put("batch_invalid_record_index",i);
                return "BATCH_REJECTED_SOURCE_WITNESS_"+i;
            }
            JSONObject event=new JSONObject();
            event.put("index",i);
            event.put("guest_syscall_number",number);
            event.put("source_locked_opcode_rip",String.format(
                Locale.ROOT,"0x%016x",opcode));
            event.put("callback_rip",String.format(
                Locale.ROOT,"0x%016x",callback));
            event.put("original_ldso_file_offset",offset);
            event.put("rip_interpretation",interp);
            event.put("original_source_witness_valid",true);
            event.put("executed_linux_syscall_semantics_proven",false);
            events.put(event);
        }
        int handled=0;
        String stop="NO_TERMINAL_PHASE_OBSERVED";
        for(int i=0;i<phases.length();++i) {
            String p=phases.optString(i,"");
            if(p.startsWith("N22_BATCH_RETURN_")) handled++;
            if(p.startsWith("E_BATCH_")) stop=p;
        }
        report.put("batch_source_locked_syscalls",events);
        report.put("batch_total_observed",count);
        report.put("batch_bounded_guest_responses",handled);
        report.put("batch_first_unhandled_index",handled<count?handled:-1);
        report.put("batch_stop_marker",stop);
        report.put("batch_was_not_full_wine_boot",true);
        report.put("batch_legacy_stages_07d_07e_07f_preserved",true);
        if(handled>=count || handled>32)
            return "BATCH_REJECTED_RESPONSE_COUNT_INCONSISTENT";
        if(count>=3 && (events.optJSONObject(0).optLong("guest_syscall_number")!=12 ||
                         events.optJSONObject(1).optLong("guest_syscall_number")!=21 ||
                         events.optJSONObject(2).optLong("guest_syscall_number")!=257))
            return "BATCH_REJECTED_FIRST_THREE_EXPECTED_SOURCE_SEQUENCE";
        if(handled>=3 && !(phases.toString().contains("J3A_R3D12_PRELOAD_ABSENT_IN_GUEST_ROOTFS") &&
                           phases.toString().contains("J3B_BATCH_CACHE_ABSENT_IN_GUEST_ROOTFS")))
            return "BATCH_REJECTED_ROOTFS_ABSENCE_PROVENANCE";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))
            return "BATCH_HALTED_AT_FIRST_UNSUPPORTED_SYSCALL";
        if(stop.equals("E_BATCH_WITNESS_CAP_32_REACHED"))
            return "BATCH_HALTED_AT_32_SYSCALL_WITNESS_LIMIT";
        return "BATCH_INCOMPLETE_OR_CHILD_EXIT_WITHOUT_TERMINAL_MARKER";
    }
'''
assert s.endswith("\n}\n"),"SOURCE_FINAL_BRACE_NOT_PRESENT"
s=s[:-2]+insert+"}\n"
for m in ("inspectBatchJournal","runBatch","BATCH_HALTED_AT_FIRST_UNSUPPORTED_SYSCALL",
          "saveReportToDownloads()","R3D9NativeCrashTrace.extract"):
    assert m in s,m
activity.write_text(s)
print("R3D13_MODE3_BATCH_32_SOURCE_LOCKED_WITNESS_JOURNAL_PATCH_PASS")
print("R3D13_07D_07E_07F_LEGACY_MODES_PRESERVED")
print("R3D13_GUEST_RESPONSES_BRK0_PRELOAD_ACCESS_CACHE_OPENAT_ONLY")
print("R3D13_NO_UNKNOWN_HOST_SYSCALL_FORWARDING_NO_FAKE_BOOT")
