#!/usr/bin/env python3
"""R3D46: fix demonstrable HOME omission in actual x86 Wine Linux initial envp.

R3D45 handset: 100/100 source-authentic callbacks then native SIGSEGV
SEGV_MAPERR at 0, worker FEXMemJIT pc, A64 ldr q20,[x4] x4/x11=0;
last guest original fex callback was close(3) on /etc/passwd fd101.
Wine 11 ntdll/unix/loader.c set_home_dir uses getenv("HOME"), then
getpwuid(getuid()), finally home_dir=strdup(home) even if home=NULL.
Original R3C23 stack provided LANG, WINEDEBUG, PATH only (no HOME/USER).
R3D46 provides HOME=/tmp and USER=wine as guest-only ABI stack
environment strings, ensuring /tmp is an owned rootfs non-symlink dir.
This is one justified causal hypothesis, NOT a claim Wine booted.
"""
from pathlib import Path
import sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_r3d46_home_env.py /tmp/carxpc")
app=Path(sys.argv[1])/"app"
launch=app/"src/main/java/com/r4/carxpc/WineLinuxProcessLaunchContract.java"
act=app/"src/main/java/com/r4/carxpc/R3D4ProbeActivity.java"
store=app/"src/main/java/com/r4/carxpc/R3D8JsonReportStore.java"
main=app/"src/main/java/com/r4/carxpc/MainActivity.java"
gradle=app/"build.gradle"
assert all(p.is_file() for p in (launch,act,store,main,gradle))
def one(s,old,new):
 count=s.count(old)
 assert count==1,("R3D46_SOURCE_DRIFT",old[:120],count)
 return s.replace(old,new,1)
s=launch.read_text()
s=one(s,
'''        StackWriter st=new StackWriter();''',
'''        // R3D46: the verified rootfs contains tmp/kernix-real-win32-smoke.exe.
        // HOME must refer to an existing directory *inside the guest*.
        // Never point guest HOME/USER to the Android app's real host path.
        Path guestHome=root.resolve("tmp");
        if(!Files.isDirectory(guestHome,LinkOption.NOFOLLOW_LINKS) ||
           Files.isSymbolicLink(guestHome))
            throw reject("R3D46_HOME_MUST_BE_APP_OWNED_GUEST_ROOTFS_DIRECTORY");
        StackWriter st=new StackWriter();''')
s=one(s,
'''long[] argv=new long[2],envp=new long[3];''',
'''long[] argv=new long[2],envp=new long[5];''')
s=one(s,
'''        envp[2]=st.pushString("PATH=/usr/bin");''',
'''        envp[2]=st.pushString("PATH=/usr/bin");
        envp[3]=st.pushString("HOME=/tmp");
        envp[4]=st.pushString("USER=wine");''')
s=one(s,
'''        // is 8 words long and AUXV is a multiple of 16 bytes; no padding''',
'''        // is 10 words long and AUXV is a multiple of 16 bytes; no padding''')
s=one(s,
'''        int aux=o+8+8*3+8*4;''',
'''        // R3D46: argc, argv2,NULL, envp5,NULL => ten 64-bit words.
        // Guard the real x86_64 stack *pointers*, not just source literals.
        if(b.getLong(o+24)!=0 || b.getLong(o+72)!=0 ||
           !guestCStringEquals(p,b.getLong(o+56),"HOME=/tmp") ||
           !guestCStringEquals(p,b.getLong(o+64),"USER=wine"))
            throw reject("R3D46_GUEST_HOME_USER_ENV_POINTER_OR_CONTENT_INVALID");
        int aux=o+8+8*3+8*6;''')
s=one(s,
'''    public static void validate(Plan p,int hostUid,int hostGid)throws IOException {''',
'''    // All strings must be NUL-terminated fully within the owned guest stack.
    // This is independent of the Android process's getenv("HOME").
    private static boolean guestCStringEquals(Plan p,long va,String expected) {
        if(va<p.stackGuestStart || va>=p.stackGuestEnd) return false;
        byte[] expectedBytes=expected.getBytes(StandardCharsets.UTF_8);
        long start=va-p.stackGuestStart;
        if(start>p.guestInitialStack.length-expectedBytes.length-1) return false;
        int offset=(int)start;
        for(int i=0;i<expectedBytes.length;i++)
            if(p.guestInitialStack[offset+i]!=expectedBytes[i])return false;
        return p.guestInitialStack[offset+expectedBytes.length]==0;
    }

    public static void validate(Plan p,int hostUid,int hostGid)throws IOException {''')
assert 'envp=new long[5]' in s
assert 'int aux=o+8+8*3+8*6;' in s
assert 'guestCStringEquals(p,b.getLong(o+56),"HOME=/tmp")' in s
launch.write_text(s)
s=act.read_text()
s=one(s,"r4.carx.r3d45.source-owned-glibc-newfstatat-fex512.v1",
         "r4.carx.r3d46.guest-home-user-env-fex512.v1")
s=one(s,"07H_R3D45_NEWFSTATAT262_AUTHENTIC_FEX512",
        "07H_R3D46_GUEST_HOME_ENV_AUTHENTIC_FEX512")
s=one(s,"07H_R3D45_NEWFSTATAT262_WINE_FEX512",
        "07H_R3D46_GUEST_HOME_ENV_WINE_FEX512")
s=one(s,"R3D45 newfstatat + Wine 512",
        "R3D46 HOME env + Wine 512")
s=one(s,
'''        report.put("r3d45_apk_runtime_identity","R3D45_v69_SOURCE_VERIFIED_LIBC_NEWFSTATAT262");''',
'''        report.put("r3d45_apk_runtime_identity","R3D45_v69_SOURCE_VERIFIED_LIBC_NEWFSTATAT262");
        report.put("r3d46_apk_runtime_identity","R3D46_v70_GUEST_HOME_TMP_USER_WINE_ABI_STACK");
        report.put("r3d46_guest_home_user_env_checked_by_abi_stack",
           phases.toString().contains("J4_WINE_LINUX_ABI_STACK_VALIDATED"));
        report.put("r3d46_guest_home_value","/tmp");
        report.put("r3d46_guest_user_value","wine");
        report.put("r3d46_original_r3d45_crash_pattern",
           "SIGSEGV_SEGV_MAPERR_ZERO_POINTER_FEX_JIT_AFTER_PASSWD");
        report.put("r3d46_native_sigsegv_prevention_not_claimed",true);''')
act.write_text(s)
s=store.read_text()
s=one(s,"CarX_PC_R3D45_Newfstatat_Diagnostics_",
        "CarX_PC_R3D46_GuestHOME_Diagnostics_")
store.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D45 — فحص ملفات Wine (newfstatat)",
        "10 | R3D46 — تصحيح HOME وUSER على Wine")
main.write_text(s)
s=gradle.read_text()
s=one(s,"versionCode 69","versionCode 70")
s=one(s,"0.69-r3d45-source-locked-newfstatat262",
        "0.70-r3d46-guest-home-env-null-crash")
gradle.write_text(s)
print("R3D46_GUEST_HOME_USER_LINUX_INITIAL_ENVP_FIVE_STRINGS_SOURCE_VALIDATED")
print("R3D46_GUEST_STACK_ENV_PTR_AND_NUL_CHECKED_AND_TMP_ROOTFS_DIR_REQUIRED")
