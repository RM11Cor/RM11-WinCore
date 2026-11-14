#!/usr/bin/env python3
"""R3C24: signed v29 Android one-click native 4K guest x86 Wine64 and
GNU ld-linux PT_LOAD staging (real kernel mmap + W^X + guest stack) stage 07B.
Never claims generalized Wine process execution or Win64 PE game boot.
"""
from pathlib import Path
import re,shutil,hashlib,sys
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
gradle=app/"app/build.gradle"
batch=java/"CarXUnifiedBatch.java"
activity=java/"MainActivity.java"
source=Path("carxpc/r3c24/android/WineX86HostMappingProbe.java")
assert all(f.is_file() for f in [gradle,batch,activity,source])
dest=java/source.name
assert not dest.exists()
shutil.copyfile(source,dest)
assert hashlib.sha256(source.read_bytes()).hexdigest()==hashlib.sha256(dest.read_bytes()).hexdigest()
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+28\b','versionCode 29',s)
assert n==1,('EXPECTED_V28',n)
s,n=re.subn(r"versionName\s+'[^']+'",
"versionName '0.29-r3c24-source-wine-native-ptload-4k'",s)
assert n==1
gradle.write_text(s)

s=batch.read_text()
needle='        boolean wineX86LinuxABIPlanReady=false;'
assert s.count(needle)==1
s=s.replace(needle,needle+'\n        WineLinuxProcessLaunchContract.Plan wineX86AbiPlan=null;')
needle='                WineLinuxProcessLaunchContract.validate(p,uid,gid);'
assert s.count(needle)==1
s=s.replace(needle,needle+'\n                wineX86AbiPlan=p;')
needle='        // This repository currently exposes the fixed original G0 native FEX'
assert s.count(needle)==1
step='''        // R3C24: real ephemeral Android Bionic kernel mmap of the source
        // SHA256-pinned original Wine64 and its GNU loader ELF64 PT_LOADs
        // into x86 guest VA with native 4K W^X and a real guest stack.
        // This stage tests NATIVE MEMORY only: no FEX guest Wine instruction
        // entry, no writes to Linux host ELF, no wineserver.
        boolean nativeWineGuestMemory4kVerified=false;
        if(wineX86LinuxABIPlanReady && wineX86AbiPlan!=null){
            try{
                JSONObject e=WineX86HostMappingProbe.probe(
                    appFiles,wineX86AbiPlan);
                nativeWineGuestMemory4kVerified=
                    e.optBoolean("native_ptload_memory_mapping_verified",false);
                add(stages,"07B_ORIGINAL_WINE_X64_NATIVE_PTLOAD_4K_MEMORY",
                    "REAL_BIONIC_MMAP_ORIGINAL_GUEST_ELF_WX_MEMORY_NOT_FEX_WINE_EXECUTION",
                    nativeWineGuestMemory4kVerified?"PASS":"FAIL",
                    nativeWineGuestMemory4kVerified?
                       "REAL_NATIVE_MMAP_4K_ORIGINAL_WINE_AND_LDSO_PTLOAD_STACK_VERIFIED_UNMAPPED_NO_EXEC":
                       "REAL_NATIVE_GUEST_VA_RESERVE_OR_WX_SEAL_FAILED",e);
            }catch(Throwable e){
                add(stages,"07B_ORIGINAL_WINE_X64_NATIVE_PTLOAD_4K_MEMORY",
                    "REAL_BIONIC_MMAP_ORIGINAL_GUEST_ELF_WX_MEMORY_NOT_FEX_WINE_EXECUTION",
                    "FAIL","WINE_NATIVE_MMAP_OR_JNI_SOURCE_GUARD_REJECTED",error(e));
            }
        }else{
            add(stages,"07B_ORIGINAL_WINE_X64_NATIVE_PTLOAD_4K_MEMORY",
                "REAL_BIONIC_MMAP_ORIGINAL_GUEST_ELF_WX_MEMORY_NOT_FEX_WINE_EXECUTION",
                "NOT_REACHED","REQUIRES_07A_AND_SOURCE_AUTHENTIC_GUEST_WINE_ABI",null);
        }

'''
s=s.replace(needle,step+needle)
needle='            report.put("original_wine_process_native_memory_mapped",false);'
assert s.count(needle)==1
s=s.replace(needle,needle+'''
            report.put("original_wine_ptload_native_4k_transient_memory_verified",
                nativeWineGuestMemory4kVerified);
            report.put("original_wine_ptload_native_mappings_still_live",false);''')
batch.write_text(s)
a=activity.read_text()
old='    addText("09 | R3-C23 اختبار موحد وتهيئة عملية Wine x64",17,ACCENT,true);'
assert a.count(old)==1
a=a.replace(old,'    addText("09 | R3-C24 فحص Wine الحقيقي داخل ذاكرة أندرويد",17,ACCENT,true);')
activity.write_text(a)
for proof in ["07B_ORIGINAL_WINE_X64_NATIVE_PTLOAD_4K_MEMORY",
              "original_wine_ptload_native_4k_transient_memory_verified",
              "WineX86HostMappingProbe.probe(", "GENERALIZED_X86_LINUX_WINE_PROCESS_ADAPTER_NOT_IMPLEMENTED"]:
    assert proof in s,proof
assert "versionCode 29" in gradle.read_text()
print("CARX_R3C24_SOURCE_AUTHENTIC_WINE_NATIVE_4K_PTLOAD_AND_WX_ONECLICK_V29_PATCH_APPLIED")
print("CARX_R3C24_STAGE07B_REAL_EPHEMERAL_NATIVE_MMAP_NO_FEX_WINE_EXEC_CLAIM")
