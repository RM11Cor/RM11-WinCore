#!/usr/bin/env python3
"""Promote original R3C25 into *opt-in* R3D4 first-syscall device probe.
No baseline R3C25 source is edited. Native loader runs only in :r3d3_probe.
The evidence file must originate from the authentic FEX HandleSyscall.
"""
from pathlib import Path
import re, shutil, sys

if len(sys.argv) != 2:
    raise SystemExit("usage: promote_first_syscall_probe.py /tmp/carxpc")
app = Path(sys.argv[1])
root = app / "app/src/main/java/com/r4/carxpc"
manifest = app / "app/src/main/AndroidManifest.xml"
gradle = app / "app/build.gradle"
source = Path("carxpc/r3c25/native/wine_x64_native_fex_context_probe.cpp")
dest = app / "app/src/main/cpp/carx_r3d4_first_syscall.cpp"
assert all(p.is_file() for p in (source, manifest, gradle, root / "WineX86HostMappingProbe.java"))
assert not dest.exists()
for name in ("R3D4ProbeActivity.java", "R3D4ProbeService.java"):
    src = Path("carxpc/r3d4/android") / name
    dst = root / name
    assert src.is_file() and not dst.exists()
    shutil.copyfile(src, dst)

m = manifest.read_text()
assert m.count("</application>") == 1
component = """
        <!-- Manual-only test icon. UI remains in main process. -->
        <activity android:name=".R3D4ProbeActivity"
                  android:exported="true"
                  android:label="CarX Wine 07D Probe">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <!-- Critical: native execution NEVER in the main UI process. -->
        <service android:name=".R3D4ProbeService"
                 android:process=":r3d3_probe"
                 android:exported="false"
                 android:stopWithTask="true" />
"""
manifest.write_text(m.replace("</application>", component + "    </application>"))

s = gradle.read_text()
s,n = re.subn(r"\bversionCode\s+30\b", "versionCode 31", s)
assert n == 1, "MUST_PATCH_R3C25_ONLY"
s,n = re.subn(r"versionName\s+'[^']+'", "versionName '0.31-r3d4-isolated-wine-first-syscall-probe'", s)
assert n == 1
gradle.write_text(s)

native = source.read_text()
assert native.count("class ExplicitNoWineExecutionSyscalls final :") == 1
assert native.count("bool createFEXContextBoundToWine(") == 1
assert native.count("context->InitCore()") == 1
assert native.count("NO ExecuteThread()") == 1
assert native.count("Java_com_r4_carxpc_WineX86FEXContextProbe_nativeProbe") == 1
assert native.count("bool run(const std::vector<uint8_t> &wine,") == 1
native = native.replace("#include <cstdio>", "#include <cstdio>\n#include <fcntl.h>\n#include \"carxpc/r3d3/native/r3d3_first_syscall_witness.hpp\"")

start = native.index("class ExplicitNoWineExecutionSyscalls final :")
end = native.index("\nbool createFEXContextBoundToWine(", start)
replacement = """class FirstSyscallCapture final : public FEXCore::HLE::SyscallHandler {
public:
  FirstSyscallCapture(uint64_t w,uint64_t l,uint64_t wineLen,uint64_t ldsoLen,
                      const std::vector<uint8_t>& source,const Elf& parsed,
                      int traceFd,uint64_t nonce)
    : WineBase(w),LdsoBase(l),WineLength(wineLen),LdsoLength(ldsoLen),
      Source(source.data()),SourceLen(source.size()),Fd(traceFd),Nonce(nonce) {
    for (const Load& seg : parsed.segments) {
      if (Count>=Loads.size()) break;
      Loads[Count++] = carx_r3d3::Load{LDSO_BIAS,seg.va,seg.fileOff,
                                        seg.fileSize,bool(seg.permission&PROT_EXEC)};
    }
  }
  void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
    // This is the *only* success path. Never forward guest syscall numbers to
    // Android Bionic. Exit only the separate :r3d3_probe process.
    if (!frame || Fd < 0 || !Nonce) ::_exit(92);
    const auto& state=frame->State;
    carx_r3d3::Record record{};
    if (!carx_r3d3::make_record(Source,SourceLen,Loads.data(),Count,
          state.rip,state.gregs[FEXCore::X86State::REG_RAX],Nonce,&record))
      ::_exit(93);
    const ssize_t n=::write(Fd,&record,sizeof(record));
    if (n!=ssize_t(sizeof(record)) || ::fsync(Fd)!=0) ::_exit(94);
    ::_exit(90);
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
      FEXCore::Core::InternalThreadState*,uint64_t address) override {
    if (address>=WineBase && address-WineBase<WineLength)
      return {WineBase,WineLength,false};
    if (address>=LdsoBase && address-LdsoBase<LdsoLength)
      return {LdsoBase,LdsoLength,false};
    return {0,0,false};
  }
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(FEXCore::Core::InternalThreadState*,
                              uint64_t) override {return std::nullopt;}
private:
  uint64_t WineBase,LdsoBase,WineLength,LdsoLength;
  std::array<carx_r3d3::Load,96> Loads{};
  size_t Count{0};
  const uint8_t* Source;
  size_t SourceLen;
  int Fd;
  uint64_t Nonce;
};"""
native = native[:start] + replacement + native[end:]

old = """bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,
                                uint64_t rsp,const Elf &main,const Elf &ldso,
                                std::string& reason) {"""
new = """bool createFEXContextBoundToWine(uint64_t wineEntry,uint64_t loaderEntry,
                                uint64_t rsp,const Elf &main,const Elf &ldso,
                                const std::vector<uint8_t>& originalLdso,
                                int traceFd,uint64_t nonce,
                                std::string& reason) {"""
assert native.count(old)==1
native=native.replace(old,new)
old = """  ExplicitNoWineExecutionSyscalls denied{
    MAIN_BIAS+main.min,LDSO_BIAS+ldso.min,main.max-main.min,ldso.max-ldso.min};
  context->SetSignalDelegator(&signals);
  context->SetSyscallHandler(&denied);"""
new = """  FirstSyscallCapture capture{
    MAIN_BIAS+main.min,LDSO_BIAS+ldso.min,main.max-main.min,ldso.max-ldso.min,
    originalLdso,ldso,traceFd,nonce};
  context->SetSignalDelegator(&signals);
  context->SetSyscallHandler(&capture);"""
assert native.count(old)==1
native=native.replace(old,new)
old = """  // IMPORTANT: NO ExecuteThread() and NO direct x86 code execution.
  // The frame is a real upstream FEXCore instance with genuine source
  // Wine and loader PT_LOADs still mapped at the exact planned addresses.
  reason="REAL_ORIGINAL_FEXCORE_CONTEXT_X86_THREAD_GNU_INTERPRETER_RIP_AND_OWNED_WINE_PTLOAD_STACK_COEXIST_NO_EXEC";
  return true;"""
new = """  // Experimental first real x86 execution; running in a 6s-killable
  // :r3d3_probe process ONLY. Success can occur only inside HandleSyscall.
  // If this returns, no verified first syscall was captured.
  context->ExecuteThread(thread);
  reason="FEX_EXECUTE_RETURNED_WITHOUT_SOURCE_LOCKED_SYSCALL";
  return false;"""
assert native.count(old)==1
native=native.replace(old,new)
old = """         const std::vector<uint8_t> &stack,uint64_t expectedWineEntry,
         uint64_t expectedLdsoEntry,uint64_t rsp,std::string &message){"""
new = """         const std::vector<uint8_t> &stack,uint64_t expectedWineEntry,
         uint64_t expectedLdsoEntry,uint64_t rsp,int traceFd,uint64_t nonce,
         std::string &message){"""
assert native.count(old)==1
native=native.replace(old,new)
old = """  if(!createFEXContextBoundToWine(expectedWineEntry,expectedLdsoEntry,rsp,
                                  we,le,message)){"""
new = """  if(!createFEXContextBoundToWine(expectedWineEntry,expectedLdsoEntry,rsp,
                                  we,le,ldso,traceFd,nonce,message)){"""
assert native.count(old)==1
native=native.replace(old,new)
old = "Java_com_r4_carxpc_WineX86FEXContextProbe_nativeProbe("
new = "Java_com_r4_carxpc_R3D4ProbeService_nativeRun("
native=native.replace(old,new)
old = """  JNIEnv *env,jclass,jbyteArray wineArray,jbyteArray ldsoArray,
  jbyteArray stackArray,jlong wineEntry,jlong ldsoEntry,jlong rsp){"""
new = """  JNIEnv *env,jclass,jbyteArray wineArray,jbyteArray ldsoArray,
  jbyteArray stackArray,jlong wineEntry,jlong ldsoEntry,jlong rsp,
  jlong nonce,jint traceFd){"""
assert native.count(old)==1
native=native.replace(old,new)
old = """  std::string msg;
  if(w.empty()||l.empty()||st.size()!=carx24::STACK_LEN)"""
new = """  std::string msg;
  // Fail closed if ever accidentally loaded in the main app process.
  char cmdline[128]{};
  int proc=::open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC);
  ssize_t nread=proc < 0 ? -1 : ::read(proc,cmdline,sizeof(cmdline));
  if(proc>=0)::close(proc);
  size_t processLen = nread<=0 ? 0 : strnlen(cmdline,size_t(nread));
  if(!carx_r3d3::exact_service_process(cmdline,processLen))
    return env->NewStringUTF("REJECTED_NOT_ISOLATED_PROBE_PROCESS");
  if(nonce<=0 || traceFd<0)
    return env->NewStringUTF("REJECTED_SESSION_OR_TRACE_FD");
  if(w.empty()||l.empty()||st.size()!=carx24::STACK_LEN)"""
assert native.count(old)==1
native=native.replace(old,new)
old = """                             uint64_t(ldsoEntry),uint64_t(rsp),msg);"""
new = """                             uint64_t(ldsoEntry),uint64_t(rsp),
                             int(traceFd),uint64_t(nonce),msg);"""
assert native.count(old)==1
native=native.replace(old,new)
# Host mapping-test alternate branch is intentionally disabled. This source
# is for the Android JNI service only. Never silently compile the host branch.
assert "context->ExecuteThread(thread)" in native
assert "ExplicitNoWineExecutionSyscalls" not in native
assert "JNIEXPORT jstring JNICALL" in native
assert "R3D4ProbeService_nativeRun" in native
assert "FEX_EXECUTE_RETURNED_WITHOUT_SOURCE_LOCKED_SYSCALL" in native
dest.write_text(native)
print("CARX_R3D4_PINNED_FEX_WINE_FIRST_SYSCALL_ISOLATED_SOURCE_PROMOTION_PASS")
