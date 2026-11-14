#!/usr/bin/env python3
"""R3D6: attach nonce-bound progress breadcrumbs to R3D4's first-syscall probe.

The R3C25 legacy batch is kept unchanged. Native checkpoints are diagnostic
markers only and cannot change the final syscall-witness acceptance criteria.
"""
from pathlib import Path
import re,sys

if len(sys.argv)!=2:
    raise SystemExit("usage: promote_phase_trace.py /tmp/carxpc")
root=Path(sys.argv[1])
gradle=root/"app/build.gradle"
activity=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
cpp=root/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
service=root/"app/src/main/java/com/r4/carxpc/R3D4ProbeService.java"
probe=root/"app/src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
assert all(x.is_file() for x in (gradle,activity,cpp,service,probe))

s=gradle.read_text()
s,n=re.subn(r"\bversionCode\s+32\b","versionCode 33",s)
assert n==1,"EXPECTED_SIGNED_R3D5_V32"
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.33-r3d6-first-syscall-phase-trace'",s)
assert n==1
gradle.write_text(s)

s=activity.read_text()
assert s.count("10 | R3D5 — اختبار Wine 07D الجديد")==1
s=s.replace("10 | R3D5 — اختبار Wine 07D الجديد",
            "10 | R3D6 — تشخيص مراحل Wine 07D",1)
activity.write_text(s)

s=cpp.read_text()
def once(old,new):
    global s
    assert s.count(old)==1,("SOURCE_BOUNDARY_CHANGED",old[:100],s.count(old))
    s=s.replace(old,new,1)

once("namespace carx24 {",'''// Kept outside R3C25 namespace; only this native library logs checkpoints.
namespace carx_r3d6 {
static int progress_fd=-1;
static void note(const char* marker) {
  if(progress_fd<0 || !marker)return;
  const size_t n=std::strlen(marker);
  if(n>0 && n<=110 && ::write(progress_fd,marker,n)==ssize_t(n) &&
     ::write(progress_fd,"\\n",1)==1) ::fsync(progress_fd);
}
}
namespace carx24 {''')
once("  Elf we{},le{};std::string why;",
     '  carx_r3d6::note("N1_NATIVE_RUN_ENTERED");\n  Elf we{},le{};std::string why;')
once('  Region wm,lm,sm;',
     '  carx_r3d6::note("N2_ELF_HEADERS_VALIDATED");\n  Region wm,lm,sm;')
once('  if(!copyAndSeal(LDSO_BIAS,ldso,le,lm,why)){',
     '  carx_r3d6::note("N3_WINE_PTLOADS_SEALED");\n  if(!copyAndSeal(LDSO_BIAS,ldso,le,lm,why)){')
once('  if(!copyStack(stack,rsp,sm,why)){',
     '  carx_r3d6::note("N4_LDSO_PTLOADS_SEALED");\n  if(!copyStack(stack,rsp,sm,why)){')
once('  const auto* entryWine=reinterpret_cast<const uint8_t*>(',
     '  carx_r3d6::note("N5_GUEST_STACK_COPIED");\n  const auto* entryWine=reinterpret_cast<const uint8_t*>(')
once('  if(!createFEXContextBoundToWine(expectedWineEntry,expectedLdsoEntry,rsp,',
     '  carx_r3d6::note("N6_SOURCE_ENTRY_VERIFIED");\n  if(!createFEXContextBoundToWine(expectedWineEntry,expectedLdsoEntry,rsp,')
once('  FEXCore::SignalDelegator signals{};',
     '  carx_r3d6::note("N7_FEX_CONTEXT_CREATED");\n  FEXCore::SignalDelegator signals{};')
once('  auto* thread=context->CreateThread();',
     '  carx_r3d6::note("N8_FEX_INITCORE_COMPLETE");\n  auto* thread=context->CreateThread();')
once('  auto& state=thread->CurrentFrame->State;',
     '  carx_r3d6::note("N9_FEX_GUEST_THREAD_CREATED");\n  auto& state=thread->CurrentFrame->State;')
once('  context->ExecuteThread(thread);',
     '  carx_r3d6::note("N10_EXECUTE_THREAD_ENTER");\n  context->ExecuteThread(thread);')
once('    const auto& state=frame->State;',
     '    carx_r3d6::note("N11_X86_SYSCALL_CALLBACK_ENTER");\n    const auto& state=frame->State;')
once('    const ssize_t n=::write(Fd,&record,sizeof(record));',
     '    carx_r3d6::note("N12_ORIGINAL_LDSO_SYSCALL_OPCODE_VERIFIED");\n    const ssize_t n=::write(Fd,&record,sizeof(record));')
once('  jlong nonce,jint traceFd){',
     '  jlong nonce,jint traceFd,jint progressFd){')
once('  if(nonce<=0 || traceFd<0)',
     '  if(nonce<=0 || traceFd<0 || progressFd<0)')
once('  if(w.empty()||l.empty()||st.size()!=carx24::STACK_LEN)',
     '  carx_r3d6::progress_fd=int(progressFd);\n  carx_r3d6::note("N0_NATIVE_JNI_ENTER");\n  if(w.empty()||l.empty()||st.size()!=carx24::STACK_LEN)')

# Critically: FEX syscall witness is unmodified. No android host-syscall forwarding.
assert '::write(Fd,&record,sizeof(record))' in s
assert 'carx_r3d3::make_record(' in s
assert 'context->ExecuteThread(thread)' in s
assert 'R3D4ProbeService_nativeRun' in s
assert 'ExplicitNoWineExecutionSyscalls' not in s
assert all("N%d_"%i in s for i in range(13))
cpp.write_text(s)
print("CARX_R3D6_PROGRESS_TRACE_SOURCE_INTEGRATION_PASS")
print("NO_GUEST_SYSCALL_HOST_FORWARDING_NO_FAKE_SUCCESS")
