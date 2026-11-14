#!/usr/bin/env python3
"""R3C25 signed v30: real FEX x86_64 CPU context and original Wine source
PT_LOAD / Linux ABI stack coexist on Android. No Wine x86 instructions run.
"""
from pathlib import Path
import hashlib,re,shutil,sys
app=Path(sys.argv[1])
root=app/'app/src/main/java/com/r4/carxpc'
gradle=app/'app/build.gradle'
batch=root/'CarXUnifiedBatch.java'
activity=root/'MainActivity.java'
src=Path('carxpc/r3c25/android/WineX86FEXContextProbe.java')
dst=root/src.name
assert all(p.is_file() for p in [gradle,batch,activity,src])
assert not dst.exists()
shutil.copyfile(src,dst)
assert hashlib.sha256(src.read_bytes()).hexdigest()==hashlib.sha256(dst.read_bytes()).hexdigest()
# SHA-pinned file-reader already audited in R3C24. Make method package-
# private so the same exact pinned byte[] is used for 07C as 07B.
reader=root/'WineX86HostMappingProbe.java'
r=reader.read_text()
old='private static byte[] pinned(Path root,String path,String expected)throws Exception{'
assert r.count(old)==1
r=r.replace(old,old.replace('private ',''))
reader.write_text(r)

s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+29\b','versionCode 30',s);assert n==1
s,n=re.subn(r"versionName\s+'[^']+'",
  "versionName '0.30-r3c25-authentic-wine-original-fexcore-live-context'",s)
assert n==1;gradle.write_text(s)

s=batch.read_text()
anchor='        // This repository currently exposes the fixed original G0 native FEX'
assert s.count(anchor)==1
step='''        // R3C25: real original pinned FEXCore JNI context and actual x86_64
        // thread frame initialized with PT_INTERP loader RIP and authentic
        // Wine Linux process stack, while native Bionic exact guest x86 4KiB
        // PT_LOAD mappings are LIVE. Executes ZERO original Wine instructions
        // so 07 remains blocked. This is a new physical device gate, not an
        // assertion inferred from 07B or any earlier FEX standalone sample.
        boolean wineFexCpuContextWithRealGuestMemoryReady=false;
        if(wineX86LinuxABIPlanReady && nativeWineGuestMemory4kVerified &&
           wineX86AbiPlan!=null){
            try{
                JSONObject evidence=WineX86FEXContextProbe.probe(
                    appFiles,wineX86AbiPlan);
                wineFexCpuContextWithRealGuestMemoryReady=evidence.optBoolean(
                    "real_original_fexcore_context_and_guest_memory_coexist",false);
                add(stages,"07C_FEX_CONTEXT_ORIGINAL_WINE_PTLOAD_LIVE",
                    "REAL_UPSTREAM_FEXCORE_X86_64_CONTEXT_AND_WINE_PTLOAD_COEXIST_NOT_EXECUTED",
                    wineFexCpuContextWithRealGuestMemoryReady?"PASS":"FAIL",
                    wineFexCpuContextWithRealGuestMemoryReady?
                        "REAL_FEX_THREAD_FRAME_PT_INTERP_RIP_AND_GUEST_STACK_WITH_LIVE_WINE_MAPS":
                        "SOURCE_LOCKED_FEX_CONTEXT_WITH_WINE_NATIVE_MEMORY_NOT_PROVEN",
                    evidence);
            }catch(Throwable e){
                add(stages,"07C_FEX_CONTEXT_ORIGINAL_WINE_PTLOAD_LIVE",
                    "REAL_UPSTREAM_FEXCORE_X86_64_CONTEXT_AND_WINE_PTLOAD_COEXIST_NOT_EXECUTED",
                    "FAIL","FEX_THREAD_CONTEXT_AND_LIVE_SOURCE_WINE_MEMORY_REJECTED",error(e));
            }
        }else{
            add(stages,"07C_FEX_CONTEXT_ORIGINAL_WINE_PTLOAD_LIVE",
                "REAL_UPSTREAM_FEXCORE_X86_64_CONTEXT_AND_WINE_PTLOAD_COEXIST_NOT_EXECUTED",
                "NOT_REACHED","REQUIRES_07A_07B_NDK_GUEST_MEMORY_AND_ABI_PLAN",null);
        }

'''
s=s.replace(anchor,step+anchor)
anchor='            report.put("original_wine_ptload_native_mappings_still_live",false);'
assert s.count(anchor)==1
s=s.replace(anchor,anchor+'''
            report.put("source_original_fexcore_live_context_with_original_wine_native_memory_verified",
                wineFexCpuContextWithRealGuestMemoryReady);
            report.put("source_original_wine_x86_first_instruction_executed",false);''')
batch.write_text(s)
a=activity.read_text()
old='    addText("09 | R3-C24 فحص Wine الحقيقي داخل ذاكرة أندرويد",17,ACCENT,true);'
assert a.count(old)==1
a=a.replace(old,'    addText("09 | R3-C25 ربط ذاكرة Wine وسياق FEX الحقيقي",17,ACCENT,true);')
activity.write_text(a)
for marker in ["07C_FEX_CONTEXT_ORIGINAL_WINE_PTLOAD_LIVE",
               "WineX86FEXContextProbe.probe(", 
               "source_original_wine_x86_first_instruction_executed", 
               "GENERALIZED_X86_LINUX_WINE_PROCESS_ADAPTER_NOT_IMPLEMENTED"]:
    assert marker in s,marker
assert 'versionCode 30' in gradle.read_text()
print("CARX_R3C25_SIGNED_ANDROID_V30_REAL_SOURCE_FEXCONTEXT_WITH_WINE64_NATIVE_PTLOAD_ONECLICK_07C_SOURCE_PATCH_OK")
print("CARX_R3C25_NO_FEX_WINE_INSTRUCTIONS_EXECUTED_SO_GUEST_PROCESS_ADAPTER_REMAINS_BLOCKED")
