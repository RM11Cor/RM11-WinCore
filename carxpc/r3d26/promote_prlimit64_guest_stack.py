#!/usr/bin/env python3
"""R3D26: real-device R3D25 libc prlimit64 (302) read-only stack query.

R3D25: 22 handled source-verified x86 syscalls, then #23 from original
verified libc FD100 was nr302 with (pid=0, resource=RLIMIT_STACK=3,
new=NULL, old=0x6FFFFFFA80 in mapped guest stack). This is NOT a source
witness failure; old Java journal validator incorrectly assumed GNU-only
guest RIP and <2MB original GNU ELF file offset for ALL records.

Keep ONE 512-event integrated FEX/Wine/Guest Linux ABI test. Boundedly copy
a read-only current guest stack limit pair into the owned guest stack.
Never grant more than the installed 64KiB stack, never forward guest
pointers to host syscalls, never modify the host process resource limits.
Correct Java source domain validation for Wine and libc records too.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_prlimit64_guest_stack.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java"; main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D26_SOURCE_ANCHOR_CHANGED",a[:135],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D26_VERSION_ANCHOR_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+53\b","versionCode 54")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.54-r3d26-owned-guest-stack-prlimit64-and-multisource-journal'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D25 — إثبات استدعاءات Wine وGNU وlibc الموحّدة",
      "10 | R3D26 — حد مكدس Wine ومصادر ELF الموحّدة")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D25_MultiELFSource_Diagnostics_"',
      '"CarX_PC_R3D26_StackPrlimit_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d25/native/verified_multi_elf_syscall.hpp"''',
'''#include "carxpc/r3d25/native/verified_multi_elf_syscall.hpp"
#include "carxpc/r3d26/native/guest_stack_prlimit64.hpp"''')
# Place AFTER all guarded guest syscalls, BEFORE the unknown-syscall stop.
# Source is already independently verified and the 56-byte witness has
# already been written in this SAME callback before reaching this handler.
s=one(s,
'''      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''',
'''      if(Mode==4 && number==carx_r3d26::kX86_64Prlimit64) {
        const uint64_t lower=carx_r3d16::kStackTop -
                            carx_r3d16::kStackSize;
        const uint64_t upper=carx_r3d16::kStackTop;
        const auto limit=carx_r3d26::query_guest_stack_prlimit64(
            arg0,arg1,arg2,arg3,lower,upper);
        if(limit.code!=carx_r3d26::StackLimitCode::Success){
          carx_r3d6::note("E_R3D26_PRLIMIT64_NOT_BOUNDED_GUEST_STACK_QUERY");
          ::_exit(176);
        }
        carx_r3d6::note("N35_X86_LIBC_PRLIMIT64_PID0_RLIMIT_STACK_READONLY");
        char limitmsg[120]{};
        std::snprintf(limitmsg,sizeof(limitmsg),
           "N35_GUEST_STACK_PRLIMIT_SOFT_%llu",
           static_cast<unsigned long long>(limit.reported.cur));
        carx_r3d6::note(limitmsg);
        std::snprintf(limitmsg,sizeof(limitmsg),
           "N35_GUEST_STACK_PRLIMIT_HARD_%llu",
           static_cast<unsigned long long>(limit.reported.max));
        carx_r3d6::note(limitmsg);
        std::snprintf(limitmsg,sizeof(limitmsg),
           "N35_GUEST_STACK_PRLIMIT_DEST_%016llX",
           static_cast<unsigned long long>(arg3));
        carx_r3d6::note(limitmsg);
        accept(0,"N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK");
        return;
      }
      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",''')
assert all(x in s for x in (
 'N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100',
 'N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK',
 'N22_BATCH_RETURN_R3D24_PRESEALED_WINE_ELF_MPROTECT',
 'N32_FEX_DYNAMIC_RX_EXECUTABLE_VMA_QUERY_ACCEPTED',
 'E_BATCH_UNSUPPORTED_NR_%llu',
 'context->ExecuteThread(thread)'))
cpp.write_text(s)

s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D25 Wine + GNU + libc Source");''',
'''runCacheless.setText("تشغيل 07H — R3D26 Wine + Guest prlimit64");''')
s=one(s,
'''r4.carx.r3d25.integrated-source-verified-multi-elf-syscalls.v1''',
'''r4.carx.r3d26.integrated-wine-source-journal-guest-prlimit64.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LINUX_ABI_TLS_THREADS_FEX_LIBC_EXEC_ELF_MULTI_SOURCE''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_SOURCE_GUEST_STACK_PRLIMIT64''')
s=one(s,
'''07H_R3D25_UNIFIED_WINE_MULTI_ELF_SOURCE_BATCH_512''',
'''07H_R3D26_UNIFIED_WINE_GUEST_STACK_PRLIMIT64_BATCH_512''')
# R3D25 validated each native 56-byte record only against GNU ld.so and
# therefore marked a *genuine verified libc record* invalid in Java. Make
# each source domain explicit, require exactly one per recorded witness, and
# apply conservative source-specific native-code-window bounds. Native
# uniquely checks exact source 0F05 bytes + file offset, Java cross-checks
# session, source sequence, bounds, and actual trusted loader/libc milestones.
s=one(s,
'''        JSONArray events=new JSONArray();
        for(int i=0;i<count;++i) {''',
'''        JSONArray events=new JSONArray();
        java.util.ArrayList<String> recordedSourceDomains=
             new java.util.ArrayList<>();
        if(currentProbeMode==4) {
          for(int p=0;p<phases.length();p++){
            String marker=phases.optString(p,"");
            if(marker.startsWith("N34_SOURCE_DOMAIN_"))
              recordedSourceDomains.add(
                marker.substring("N34_SOURCE_DOMAIN_".length()));
          }
          if(recordedSourceDomains.size()!=count) {
            report.put("r3d26_source_domain_events",recordedSourceDomains.size());
            report.put("r3d26_wire_witness_count",count);
            return "BATCH_REJECTED_SOURCE_DOMAIN_WIRE_EVENT_COUNT_MISMATCH";
          }
        }
        for(int i=0;i<count;++i) {''')
s=one(s,
'''            boolean valid=magic==0x33443352 && version==2 &&
                nonce==expectedNonce && number<=0xFFFFFFFFL &&
                opcode>=LOADER_BIAS && opcode-LOADER_BIAS<0x1000000L &&
                offset<0x200000L && reserved==0 &&
                ((interp==1 && callback==opcode) ||
                 (interp==2 && callback==opcode+2));''',
'''            final String sourceDomain=currentProbeMode==4?
              recordedSourceDomains.get(i):"GNU_LDSO";
            final long WINE_BIAS=0x0000004000000000L;
            final boolean gnuRange="GNU_LDSO".equals(sourceDomain) &&
              opcode>=LOADER_BIAS && opcode-LOADER_BIAS<0x1000000L &&
              offset>=0 && offset<0x200000L;
            final boolean wineRange="WINE_ELF".equals(sourceDomain) &&
              opcode>=WINE_BIAS && opcode-WINE_BIAS<0x1000000L &&
              offset>=0 && offset<0x200000L &&
              phases.toString().contains("J5_WINE_SHA256_VERIFIED");
            final boolean libcRange="VERIFIED_LIBC_FD100".equals(sourceDomain) &&
              opcode>0x10000L && opcode<0x0000800000000000L &&
              offset>=0 && offset<32L*1024L*1024L &&
              phases.toString().contains(
                "J3D_R3D17_LIBC_ROOTFS_READONLY_FD_VERIFIED") &&
              phases.toString().contains(
                "N32_GUEST_LIBC_RX_MMAP_REGISTERED_FOR_FEX");
            boolean valid=magic==0x33443352 && version==2 &&
                nonce==expectedNonce && number>=0 && number<=0xFFFFFFFFL &&
                (gnuRange || wineRange || libcRange) &&
                reserved==0 &&
                ((interp==1 && callback==opcode) ||
                 (interp==2 && opcode<=Long.MAX_VALUE-2 &&
                  callback==opcode+2));''')
s=one(s,
'''            event.put("original_ldso_file_offset",offset);''',
'''            event.put("source_domain",sourceDomain);
            event.put("original_elf_file_offset",offset);
            if("GNU_LDSO".equals(sourceDomain))
              event.put("original_ldso_file_offset",offset);''')
s=one(s,
'''        report.put("r3d25_verified_guest_elf_domain_required",true);''',
'''        report.put("r3d25_verified_guest_elf_domain_required",true);
        report.put("r3d26_readonly_rlimit_stack_source_302",true);
        report.put("r3d26_prlimit64_guest_stack_query_accepted",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK"));
        report.put("r3d26_stack_is_bounded_diagnostic_not_autogrowing",true);
        report.put("r3d26_guest_prlimit_host_setrlimit_or_ptr_forwarded",false);
        report.put("r3d26_original_libc_source_domain_confirmed",
          phases.toString().contains(
            "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100"));
        report.put("r3d26_multisource_journal_validation_enabled",true);''')
s=one(s,
'''        stages.put("unknown_original_x86_syscall_source_rejected",
          phases.toString().contains(
           "E_R3D25_SYSCALL_SOURCE_UNPROVEN_OR_AMBIGUOUS"));''',
'''        stages.put("unknown_original_x86_syscall_source_rejected",
          phases.toString().contains(
           "E_R3D25_SYSCALL_SOURCE_UNPROVEN_OR_AMBIGUOUS"));
        stages.put("prlimit64_rlimit_stack_owned_guest_result",
          phases.toString().contains(
           "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK"));''')
s=one(s,
'''R3D25 preserves all R3D24 RELRO/FEX TLS/syscall work. Actual R3D24 phone trace: original GNU ld.so completed 22/22 x86 guest callbacks, including Wine and GNU source-sealed RELRO; then callback entered but exited with legacy witness failure 93 before syscall identity logging. The R3D3 original witness checker matched GNU ld.so ELF only. R3D25 requires a unique authentic x86 opcode in one of THREE original verified ELF sources: GNU ld.so original byte-backed PT_LOAD, Wine original byte-backed PT_LOAD, or verified readonly libc fd100 file offset from owned, still source-identical RX guest mapping. Unknown/ambiguous callback RIP and syscall number are recorded and rejected without host forwarding, with per-witness source domain in one batch JSON. Does NOT prove full Wine Linux ABI/Win64 PE/graphics/game.''',
'''R3D26 preserves R3D25 native source-verified GNU/Wine/libc x86 syscalls and all 22 handled calls. Real R3D25 device result proved original libc FD100 syscall 302 prlimit64(pid=0, resource=3 RLIMIT_STACK, new=null, old=owned guest stack); stopped as unsupported (113). Old Java wire validator wrongly expected only GNU ld.so and labelled this valid libc record source failure. R3D26 repairs Java per-record source domain validation and handles ONLY read-only guest RLIMIT_STACK into the installed writable 64KiB guest stack, capped by existing host resource limits, without host limit mutation or guest pointer forwarding. Diagnostic guest stack cannot auto-grow; full Linux ABI, Wine, Win64 PE/graphics/game remain unproven.''')
act.write_text(s)
print("R3D26_ORIGINAL_X86_LIBC_PRLIMIT64_GUEST_STACK_SOURCE_PROMOTION_PASS")
print("R3D26_JAVA_WITNESS_GNU_WINE_LIBC_DOMAIN_PER_RECORD_CORRECTED")
print("R3D26_NO_HOST_RLIMIT_MODIFICATION_NO_GUEST_HOST_PTR_FORWARDING")
