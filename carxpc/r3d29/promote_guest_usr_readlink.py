#!/usr/bin/env python3
"""R3D29: handle the real original x86 libc readlink(89) of guest /usr.

R3D28 on-device witness batch 28 original GNU+libc x86 syscall records;
27 bounded responses including source-verified procfs realpath components,
then exact N36 HEX_PREFIX_2F757372 = "/usr" at witness index 27,
returning guarded unknown path - exit 178. Correct Linux readlink(2)
on an existing NON-SYMLINK directory is -EINVAL, without modifying buffer.

Only the directory components of the already authenticated guest Wine
launch contract "/usr/lib/wine/wine64" are considered; /lib is NOT assumed
a directory (can be a real symlink). Preserve source-verified GNULD, Wine,
libc and all previous 512-witness batch behavior. No arbitrary guest path
ever passed through to Android host file APIs or rootfs parent probing.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit("usage: promote_guest_usr_readlink.py /tmp/carxpc")
app=Path(sys.argv[1]);java=app/"app/src/main/java/com/r4/carxpc"
cpp=app/"app/src/main/cpp/carx_r3d4_first_syscall.cpp"
act=java/"R3D4ProbeActivity.java";main=java/"MainActivity.java"
gradle=app/"app/build.gradle";store=java/"R3D8JsonReportStore.java"
assert all(x.is_file() for x in (cpp,act,main,gradle,store))
def one(s,a,n):
 c=s.count(a)
 assert c==1,("R3D29_SOURCE_LOCK_ANCHOR_CHANGED",a[:150],c)
 return s.replace(a,n,1)
def reone(s,p,n):
 s,k=re.subn(p,n,s,count=1)
 assert k==1,("R3D29_VERSION_SOURCE_CHANGED",p,k)
 return s
s=gradle.read_text()
s=reone(s,r"\bversionCode\s+56\b","versionCode 57")
s=reone(s,r"versionName\s+'[^']+'",
 "versionName '0.57-r3d29-source-verified-guest-usr-nonlink-components'")
gradle.write_text(s)
s=main.read_text()
s=one(s,"10 | R3D28 — معالجة مسارات procfs للضيف",
      "10 | R3D29 — معالجة مجلدات Wine للضيف")
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D28_ProcfsComponents_Diagnostics_"',
      '"CarX_PC_R3D29_WineUsrPaths_Diagnostics_"')
store.write_text(s)
s=cpp.read_text()
s=one(s,
'''#include "carxpc/r3d28/native/verified_guest_procfs_components.hpp"''',
'''#include "carxpc/r3d28/native/verified_guest_procfs_components.hpp"
#include "carxpc/r3d29/native/source_verified_usr_components.hpp"''')
s=one(s,
'''          const auto procfs=carx_r3d28::resolve_known_procfs_component(
              observed,arg1,arg2,stackLow,stackHigh,isolatedWorkerPid);''',
'''          // Guest Wine executable was source SHA verified and sealed.
          // Never present Android's /usr or /proc to the x86 guest.
          // These exact prefix components are directories of the authenticated
          // Linux rootfs guest executable path, not symbolic links.
          const auto wineDir=carx_r3d29::query_readlink_non_symlink(
              observed,arg1,arg2,stackLow,stackHigh,
              PresealedWineVerified);
          if(wineDir.kind==carx_r3d29::Kind::BadOutputRegion){
            carx_r3d6::note("E_R3D29_UNOWNED_READLINK_OUTPUT");
            ::_exit(181);
          }
          if(wineDir.kind==carx_r3d29::Kind::MissingOriginalWineEvidence){
            carx_r3d6::note("E_R3D29_ORIGINAL_WINE_EVIDENCE_MISSING");
            ::_exit(182);
          }
          if(wineDir.kind==carx_r3d29::Kind::VerifiedNonSymlinkDirectory){
            carx_r3d6::note("N38_SOURCE_VERIFIED_WINE_ROOTFS_NONLINK_COMPONENT");
            if(std::strcmp(observed,"/usr")==0)
              carx_r3d6::note("N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY");
            else
              carx_r3d6::note("N38_ORIGINAL_GUEST_WINE_EXECFN_DIRECTORY_COMPONENT");
            accept(-int64_t(EINVAL),
                "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL");
            return;
          }
          const auto procfs=carx_r3d28::resolve_known_procfs_component(
              observed,arg1,arg2,stackLow,stackHigh,isolatedWorkerPid);''')
assert all(x in s for x in (
 "N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY",
 "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL",
 "N22_BATCH_RETURN_R3D28_PROCFS_DIR_NEG_EINVAL",
 "N22_BATCH_RETURN_R3D28_PROC_SELF_GUEST_PID_SYMLINK",
 "N22_BATCH_RETURN_R3D26_PRLIMIT64_OWNED_GUEST_STACK",
 "N34_SOURCE_DOMAIN_VERIFIED_LIBC_FD100",
 "E_R3D27_READLINK_UNSUPPORTED_GUEST_SYMLINK",
 "context->ExecuteThread(thread)"))
cpp.write_text(s)
s=act.read_text()
s=one(s,
'''runCacheless.setText("تشغيل 07H — R3D28 Wine + procfs readlink");''',
'''runCacheless.setText("تشغيل 07H — R3D29 Wine + /usr readlink");''')
s=one(s,
'''r4.carx.r3d28.integrated-guest-procfs-component-readlink.v1''',
'''r4.carx.r3d29.integrated-guest-wine-usr-directory-readlink.v1''')
s=one(s,
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_PROCFS_COMPONENT_READLINK''',
'''07H_INTEGRATED_WINE_GNU_LDSO_LIBC_WINE_USR_DIRECTORY_READLINK''')
s=one(s,
'''07H_R3D28_UNIFIED_WINE_GUEST_PROCFS_READLINK_BATCH_512''',
'''07H_R3D29_UNIFIED_WINE_GUEST_USR_READLINK_BATCH_512''')
s=one(s,
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_"))
              stop=p;''',
'''if(p.startsWith("E_BATCH_") || p.startsWith("E_R3D22_") ||
             p.startsWith("E_R3D25_") || p.startsWith("E_R3D27_") ||
             p.startsWith("E_R3D29_"))
              stop=p;''')
s=one(s,
'''        report.put("r3d28_unknown_guest_path_host_forwarded",false);''',
'''        report.put("r3d28_unknown_guest_path_host_forwarded",false);
        report.put("r3d29_usr_readlink_directory_einval_handled",
          phases.toString().contains(
            "N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY") &&
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL"));
        report.put("r3d29_verified_guest_wine_directory_component_einval",
          phases.toString().contains(
            "N38_ORIGINAL_GUEST_WINE_EXECFN_DIRECTORY_COMPONENT"));
        report.put("r3d29_guest_usr_source_verified_nonlink_component",
          phases.toString().contains(
            "N38_SOURCE_VERIFIED_WINE_ROOTFS_NONLINK_COMPONENT"));
        report.put("r3d29_guest_host_path_readlink_forwarded",false);
        report.put("r3d29_wine_rootfs_path_scope",
          "EXACT_PARENT_DIRECTORY_COMPONENTS_OF_AUTHENTICATED_USR_LIB_WINE_WINE64");''')
s=one(s,
'''        stages.put("guest_proc_pid_exe_readlink",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK"));''',
'''        stages.put("guest_proc_pid_exe_readlink",
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D28_PROC_GUEST_PID_EXE_SYMLINK"));
        stages.put("guest_wine_rootfs_usr_directory_readlink_nonlink",
          phases.toString().contains(
            "N38_EXACT_ORIGINAL_GUEST_READLINK_USR_DIRECTORY") &&
          phases.toString().contains(
            "N22_BATCH_RETURN_R3D29_WINE_USR_DIR_NEG_EINVAL"));''')
s=one(s,
'''R3D28 preserves all 24 original x86 GNU+libc syscall source witness records and 23 accepted responses proven by R3D27. The R3D27 device report decoded the exact readlink nr89 source-owned path HEX 2F70726F63 as /proc, a guest procfs DIRECTORY not symlink; correct Linux return is -EINVAL without writing output, not success or a host filesystem path. R3D28 safely supports this directory and bounded related /proc/self symlink to the actual isolated worker PID, /proc/<pid> directory, /proc/<pid>/exe original SHA-authenticated guest Wine execfn; legacy /proc/self/exe unchanged. Any other path still fails closed with hex source. All guest readlink output is in the mapped 64 KiB x86 guest stack, never from host readlink or host executable. Java now describes unsupported verified guest readlink explicitly, not generic child exit. Preserves one 512-witness Wine/FEX/Linux ABI batch; full Wine/Win64 PE/graphics/game remain unproven.''',
'''R3D29 preserves all R3D28 source-verified 28 original GNU/ELF/libc x86 syscall records and 27 accepted Linux guest responses. In actual R3D28 phone trace readlink nr89 at index27 was source-authenticated libc, guest path hex 2F757372 = /usr. Existing Wine guest launch contract has SHA-verified /usr/lib/wine/wine64 ELF, with fixed guest directory chain root, /usr, /usr/lib, /usr/lib/wine. For these ONLY, readlink returns Linux -EINVAL without copying any output bytes; host paths never read or returned. Unknown paths still fail closed with bounded hex witness. Prior /proc links and Wine/ldso source PTLOAD protection retained in the ONE 512-event batch. A full guest filesystem, Linux process ABI, Wine, Win64 PE, graphics and game boot remain unproven.''')
act.write_text(s)
print("R3D29_USR_GUEST_WINE_ROOTFS_SOURCE_PINNED_READLINK_EINVAL_PATCH_PASS")
print("R3D29_NO_HOST_READLINK_NO_UNVERIFIED_GUEST_NONLINK_ACCEPTANCE")
