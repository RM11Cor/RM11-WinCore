// Host security regression for an Android CI-only FEX runtime candidate.
// Does not build the original FEX JIT or execute guest x86/ELF.
#include "kernix_g2c_fixed_android_candidate_gate.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
using kernix::g2c::IsFixedDeviceCandidateInvocation;
using kernix::g2c::kFixedDeviceRunFlag;

static bool Check(int count,const char* flag,const char* directory) {
    const char* args[]={"libkernix_g2c_android_direct_pie_probe.so",
                         flag,directory,nullptr};
    return IsFixedDeviceCandidateInvocation(count,args);
}
int main() {
    for(const char* path : std::array<const char*,5>{
      "/data/user/0/org.kernix.host/files",
      "/data/user/10/org.kernix.host/files",
      "/data/user/123/org.kernix.host/files",
      "/data/user_de/10/org.kernix.host/files",
      "/data/data/org.kernix.host/files"}) {
      assert(Check(3,kFixedDeviceRunFlag,path));
      assert(kernix::g2c::IsMITDeviceCandidateInvocation(3,
          std::array<const char*,3>{
            "libkernix_g2c_mit_fex_candidate.so",
            kernix::g2c::kMITDeviceRunFlag,path}.data()));
    }
    const char* invalid[]={
      "/",
      ".",
      "/sdcard/org.kernix.host/files",
      "/mnt/sdcard/org.kernix.host/files",
      "/tmp/org.kernix.host/files",
      "/data/user/org.kernix.host/files",
      "/data/user/x/org.kernix.host/files",
      "/data/user/0/com.other.host/files",
      "/data/user/0/org.kernix.host/files/extra",
      "/data/user/0/org.kernix.host/files/",
      "/data/user/0/../0/org.kernix.host/files",
      "/data/user/0//org.kernix.host/files",
      "/data/user/0/./org.kernix.host/files",
      "/data/user_de/../org.kernix.host/files",
      "/data/../data/data/org.kernix.host/files",
      "/data/user_de/x/org.kernix.host/files",
      "/data/user/00/org.kernix.host/files",
      "/data/data/org.kernix.host/files/../../other",
      "/data/data/org.kernix.host/files2",
      "/data/data/org.kernix.host/files//"
    };
    for(const char* path:invalid) {
      assert(!Check(3,kFixedDeviceRunFlag,path));
      const std::array<const char*,3> mit{
          "libkernix_g2c_mit_fex_candidate.so",
          kernix::g2c::kMITDeviceRunFlag,path
      };
      assert(!kernix::g2c::IsMITDeviceCandidateInvocation(3,mit.data()));
    }
    assert(!Check(3,"--execute-any-elf","/data/user/0/org.kernix.host/files"));
    assert(!Check(3,"--fixed-data-only-preflight","/data/user/0/org.kernix.host/files"));
    assert(!Check(3,nullptr,"/data/user/0/org.kernix.host/files"));
    assert(!Check(3,kFixedDeviceRunFlag,nullptr));
    assert(!Check(2,kFixedDeviceRunFlag,"/data/user/0/org.kernix.host/files"));
    assert(!Check(4,kFixedDeviceRunFlag,"/data/user/0/org.kernix.host/files"));
    assert(!IsFixedDeviceCandidateInvocation(3,nullptr));
    const char* args[]={nullptr,kFixedDeviceRunFlag,"/data/user/0/org.kernix.host/files"};
    assert(!IsFixedDeviceCandidateInvocation(3,args));
    char huge[1200]{};
    std::memset(huge,'a',sizeof(huge)-1);
    assert(!Check(3,kFixedDeviceRunFlag,huge));
    const std::array<const char*,3> mismatched{
        "libkernix_g2c_mit_fex_candidate.so",
        kFixedDeviceRunFlag,
        "/data/user/0/org.kernix.host/files"
    };
    assert(!kernix::g2c::IsMITDeviceCandidateInvocation(3,mismatched.data()));
    const std::array<const char*,3> mitFlag{
        "libkernix_g2c_mit_fex_candidate.so",
        kernix::g2c::kMITDeviceRunFlag,
        "/data/user/0/org.kernix.host/files"
    };
    assert(!IsFixedDeviceCandidateInvocation(3,mitFlag.data()));
    assert(!kernix::g2c::IsMITDeviceCandidateInvocation(2,mitFlag.data()));
    assert(!kernix::g2c::IsMITDeviceCandidateInvocation(4,mitFlag.data()));
    std::puts("KERNIX_G2C_MIT_ANDROID_FIXED_APP_PRIVATE_COMMAND_REJECTS_GLIBC_AND_EXTERNAL_ELFS");
    std::puts("KERNIX_G2C_ANDROID_CANDIDATE_CLI_EXACT_ALLOWLIST_HOST_PASS_NO_DEVICE_EXEC");
    return 0;
}
