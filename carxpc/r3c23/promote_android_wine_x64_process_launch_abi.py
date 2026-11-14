#!/usr/bin/env python3
"""CarX R3C23: add on-device source-authentic Wine x86-64 Linux process ABI
launch plan 07A to existing signed v27 one-click 10-stage Android app, v28.

07A creates REAL Linux-x64 argv/envp/AUXV bytes from SHA-locked wine64 and
ld.so. It does not mmap x86 guest code or claim Wine64/Win64 PE run.
"""
from pathlib import Path
import hashlib,re,shutil,sys
app=Path(sys.argv[1])
root=app/"app/src/main/java/com/r4/carxpc"
activity=root/"MainActivity.java"
gradle=app/"app/build.gradle"
batch=root/"CarXUnifiedBatch.java"
source=Path("carxpc/r3c23/android/WineLinuxProcessLaunchContract.java")
assert all(p.is_file() for p in [activity,gradle,batch,source])
dst=root/source.name
assert not dst.exists(),"R3C23_LAUNCH_PLAN_ALREADY_EXISTED"
shutil.copyfile(source,dst)
assert hashlib.sha256(dst.read_bytes()).digest()==hashlib.sha256(source.read_bytes()).digest()

s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+27\b','versionCode 28',s)
assert n==1,("R3C22_EXPECTED_SIGNED_27",n)
s,n=re.subn(r"versionName\s+'[^']+'",
"versionName '0.28-r3c23-real-wine-linux-x64-guest-process-abi-plan'",s)
assert n==1
gradle.write_text(s)

s=batch.read_text()
mark='        // This repository currently exposes the fixed original G0 native FEX'
assert s.count(mark)==1
extension='''        // R3C23: source-authentic original Wine64/ld-linux x86_64 Linux
        // process startup ABI. This plans guest virtual addresses and encodes
        // actual byte-for-byte argc/argv/envp/auxv/AT_RANDOM in a 64KiB
        // synthetic guest stack buffer. It does NOT reserve native guest
        // memory or execute original Wine instructions through FEX yet.
        boolean wineX86LinuxABIPlanReady=false;
        if(elfReady){
            try{
                long nativePageValue=android.system.Os.sysconf(
                    android.system.OsConstants._SC_PAGESIZE);
                if(nativePageValue!=4096L && nativePageValue!=16384L)
                    throw new java.io.IOException("NATIVE_ANDROID_PAGE_SIZE_UNSUPPORTED_FOR_PLAN");
                int uid=android.os.Process.myUid();
                int gid=android.system.Os.getgid();
                WineLinuxProcessLaunchContract.Plan p=
                    WineLinuxProcessLaunchContract.prepare(
                        appFiles,(int)nativePageValue,uid,gid);
                WineLinuxProcessLaunchContract.validate(p,uid,gid);
                wineX86LinuxABIPlanReady=p.sourceShaVerified&&
                    p.actualX86InitialStackEncoded&&
                    !p.guestHostMemoryReserved&&
                    !p.guestWineCodeTranslated&&
                    !p.wineProcessExecuted&&
                    !p.guestSyscallBridgeComplete;
                JSONObject e=new JSONObject();
                e.put("guest_linux_abi","linux-x86_64-sysv")
                 .put("source_sha_wine64",WineGuestElfPreflight.WINE64_SHA256)
                 .put("source_sha_interpreter",WineGuestElfPreflight.LDSO_SHA256)
                 .put("main_elf_ptload_count",p.wine.loadSegments.size())
                 .put("ldso_elf_ptload_count",p.ldso.loadSegments.size())
                 .put("main_file_size",p.wine.fileSize)
                 .put("ldso_file_size",p.ldso.fileSize)
                 .put("guest_wine_main_entry_virtual",
                    String.format(java.util.Locale.ROOT,"0x%016x",p.guestWineEntry))
                 .put("guest_interpreter_entry_virtual",
                    String.format(java.util.Locale.ROOT,"0x%016x",p.guestLoaderEntry))
                 .put("guest_auxv_phdr_virtual",
                    String.format(java.util.Locale.ROOT,"0x%016x",p.guestPHDR))
                 .put("guest_argv",new JSONArray(new String[]{
                    WineLinuxProcessLaunchContract.GUEST_EXECFN,"--version"}))
                 .put("guest_argc",2)
                 .put("guest_envc",3)
                 .put("guest_initial_stack_bytes",p.guestInitialStack.length)
                 .put("guest_rsp_16byte_aligned",p.stackRSP%16==0)
                 .put("guest_linux_auxv_source_addresses_checked",true)
                 .put("native_android_page_size",p.observedHostNativePageSize)
                 .put("guest_linux_page_size",p.guestPageSize)
                 .put("native_16k_guest_4k_subpage_mediation_still_required",
                    p.requires16kNativeSubpageProtection)
                 .put("guest_initial_stack_encoded_not_mapped",true)
                 .put("native_guest_memory_reserved",p.guestHostMemoryReserved)
                 .put("wine_x86_code_translated",p.guestWineCodeTranslated)
                 .put("wine_process_executed",p.wineProcessExecuted)
                 .put("wineserver_spawned",p.wineserverSpawned)
                 .put("guest_linux_syscall_bridge_complete",p.guestSyscallBridgeComplete)
                 .put("real_windows_game_boot_proven",false);
                add(stages,"07A_WINE_LINUX_X64_PROCESS_ABI_LAUNCH_PLAN",
                    "ORIGINAL_ELF_SOURCE_SHA_GUEST_ARGV_ENVP_AUXV_NOT_EXECUTION",
                    wineX86LinuxABIPlanReady?"PASS":"FAIL",
                    wineX86LinuxABIPlanReady?
                       "SOURCE_AUTHENTIC_WINE64_AND_LDSO_X86_GUEST_ABI_STACK_READY_NO_EXEC":
                       "WINE_GUEST_LINUX_X64_PROCESS_ABI_PLAN_NOT_PROVEN",e);
            }catch(Throwable e){
                add(stages,"07A_WINE_LINUX_X64_PROCESS_ABI_LAUNCH_PLAN",
                    "ORIGINAL_ELF_SOURCE_SHA_GUEST_ARGV_ENVP_AUXV_NOT_EXECUTION",
                    "FAIL","AUTHENTIC_WINE_LINUX_X64_STACK_OR_AUXV_PLAN_REJECTED",error(e));
            }
        }else{
            add(stages,"07A_WINE_LINUX_X64_PROCESS_ABI_LAUNCH_PLAN",
                "ORIGINAL_ELF_SOURCE_SHA_GUEST_ARGV_ENVP_AUXV_NOT_EXECUTION",
                "NOT_REACHED","DEPENDENCY_04_WINE_ELF_SOURCE_SHA_NOT_VERIFIED",null);
        }

'''
s=s.replace(mark,extension+mark)
old='            report.put("rootfs_metadata_verified",elfReady);'
assert s.count(old)==1
s=s.replace(old,old+'''
            report.put("original_wine_x64_linux_process_abi_plan_verified",
                wineX86LinuxABIPlanReady);
            report.put("wine_argv_envp_auxv_synthetic_guest_stack_verified",
                wineX86LinuxABIPlanReady);
            report.put("original_wine_process_native_memory_mapped",false);
            report.put("original_wine_process_genuine_fex_execution_proven",false);''')
batch.write_text(s)
a=activity.read_text()
look='    addText("09 | R3-C20 اختبار واحد لجميع مراحل الربط والتشخيص",17,ACCENT,true);'
replace='    addText("09 | R3-C23 اختبار موحد وتهيئة عملية Wine x64",17,ACCENT,true);'
assert a.count(look)==1
a=a.replace(look,replace)
activity.write_text(a)
for key in ['07A_WINE_LINUX_X64_PROCESS_ABI_LAUNCH_PLAN',
            'original_wine_x64_linux_process_abi_plan_verified',
            'GENERALIZED_X86_LINUX_WINE_PROCESS_ADAPTER_NOT_IMPLEMENTED',
            '"original_wine_process_genuine_fex_execution_proven",false']:
    assert key in s,key
assert 'versionCode 28' in gradle.read_text()
print("CARX_R3C23_SIGNED_V28_AUTHENTIC_WINE64_X64_GUEST_ABI_PREPARED_ONECLICK_STAGE_07A")
print("CARX_R3C23_V28_ANDROID_LAUNCH_PLAN_NO_FEX_WINE_EXECUTION_OR_WINESERVER_SPOOF")
