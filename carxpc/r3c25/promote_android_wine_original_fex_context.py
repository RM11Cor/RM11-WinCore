#!/usr/bin/env python3
"""R3C25 v30. Reuse proven 07A and 07B original Wine startup/host mapping,
then create REAL upstream FEXCore ARM64 x86_64 context/thread with source
GNU ld-linux RIP and Linux argv/envp/auxv RSP simultaneously mapped.
IMPORTANT: no ExecuteThread(), guest instruction execution, Wine, Win64 PE
or CarX boot is implied by successful 07C.
"""
from pathlib import Path
import re,hashlib,shutil,sys
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
activity=java/"MainActivity.java";batch=java/"CarXUnifiedBatch.java"
gradle=app/"app/build.gradle"
src=Path("carxpc/r3c25/android/WineX86FEXContextProbe.java")
for p in (activity,batch,gradle,src):assert p.is_file(),p
dest=java/src.name
assert not dest.exists(),"R3C25_PROBE_ALREADY_IN_APP"
shutil.copyfile(src,dest)
assert hashlib.sha256(dest.read_bytes()).digest()==hashlib.sha256(src.read_bytes()).digest()
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+29\b','versionCode 30',s)
assert n==1,("R3C24_EXPECTED_VERSION_29",n)
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.30-r3c25-wine-fex-x86-context-coexist-no-exec'",s)
assert n==1
gradle.write_text(s)
s=batch.read_text()
anchor='        // This repository currently exposes the fixed original G0 native FEX'
assert s.count(anchor)==1
insert='''        // R3C25: SAME guest source ELF image bytes and GNU x64 initial
        // Linux stack, but now real upstream ARM64 FEXCore Context::
        // CreateNewContext, InitCore, CreateThread, and original
        // ld-linux entry RIP. Mappings coexist with the FEX thread.
        // Explicitly NO context->ExecuteThread here, and every syscall
        // request would fail closed (no guest host pass-through).
        boolean originalWineFexContextCoexistReady=false;
        if(wineX86LinuxABIPlanReady && nativeWineGuestMemory4kVerified &&
           wineX86AbiPlan!=null){
            try{
                JSONObject e=WineX86FEXContextProbe.probe(
                    appFiles,wineX86AbiPlan);
                originalWineFexContextCoexistReady=
                    e.optBoolean("real_original_fexcore_context_and_guest_memory_coexist",false);
                add(stages,"07C_ORIGINAL_FEX_WINE_X64_GUEST_CONTEXT_COEXIST",
                    "REAL_ORIGINAL_FEXCORE_CONTEXT_THREAD_ELF_PTLOAD_RIP_RSP_NO_X86_EXEC",
                    originalWineFexContextCoexistReady?"PASS":"FAIL",
                    originalWineFexContextCoexistReady?
                        "ORIGINAL_FEXCORE_X86_64_CONTEXT_AND_GNU_LDSO_ENTRY_RIP_GUEST_STACK_COEXIST_NOT_EXECUTED":
                        "FEXCORE_CONTEXT_INIT_OR_WINE_VA_COEXIST_FAILED",e);
            }catch(Throwable e){
                add(stages,"07C_ORIGINAL_FEX_WINE_X64_GUEST_CONTEXT_COEXIST",
                    "REAL_ORIGINAL_FEXCORE_CONTEXT_THREAD_ELF_PTLOAD_RIP_RSP_NO_X86_EXEC",
                    "FAIL","R3C25_FEXCORE_CONTEXT_NATIVE_OR_GUEST_SOURCE_GUARD_REJECTED",error(e));
            }
        }else{
            add(stages,"07C_ORIGINAL_FEX_WINE_X64_GUEST_CONTEXT_COEXIST",
                "REAL_ORIGINAL_FEXCORE_CONTEXT_THREAD_ELF_PTLOAD_RIP_RSP_NO_X86_EXEC",
                "NOT_REACHED","NEEDS_07A_07B_REAL_WINE_DATA_PTLOAD_AND_STACK",null);
        }

'''
s=s.replace(anchor,insert+anchor)
anchor='            report.put("original_wine_ptload_native_mappings_still_live",false);'
assert s.count(anchor)==1
s=s.replace(anchor,anchor+'''
            report.put("original_wine_fex_core_x86_context_coexist_verified",
                originalWineFexContextCoexistReady);
            report.put("original_wine_fex_guest_instructions_executed",false);
            report.put("original_wine_fex_guest_syscalls_executed",false);''')
batch.write_text(s)
a=activity.read_text()
old='    addText("09 | R3-C24 فحص Wine الحقيقي داخل ذاكرة أندرويد",17,ACCENT,true);'
assert a.count(old)==1
a=a.replace(old,'    addText("09 | R3-C25 فحص ربط ذاكرة Wine مع سياق FEX",17,ACCENT,true);')
activity.write_text(a)
for required in ['07C_ORIGINAL_FEX_WINE_X64_GUEST_CONTEXT_COEXIST',
                 'WineX86FEXContextProbe.probe(','original_wine_fex_guest_instructions_executed",false',
                 'GENERALIZED_X86_LINUX_WINE_PROCESS_ADAPTER_NOT_IMPLEMENTED']:
    assert required in s,required
assert "versionCode 30" in gradle.read_text()
print("CARX_R3C25_ONECLICK_V30_REAL_FEXCORE_CONTEXT_AND_ORIGINAL_WINE_MAPPED_4K_VA_SOURCE_PROOF_INTEGRATED")
print("CARX_R3C25_NO_GUEST_INSTRUCTION_OR_WINESERVER_EXECUTION_CLAIM")
