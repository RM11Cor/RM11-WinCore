// SPDX-License-Identifier: MIT
// Real ARM64 host guarded x86 initial process-entry stack installed from
// SHA-pinned GNU main/ld-linux/libc metadata. NO FEX/ldso/glibc execution.
#include "kernix_g0_owned_original_guest_startup_stack.h"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace {
uint64_t LoadLE(const uint8_t* memory,size_t pos,size_t capacity) {
    assert(memory && pos<=capacity && capacity-pos>=8);
    uint64_t x=0;
    for(unsigned i=0;i<8;++i)x|=uint64_t(memory[pos+i])<<(8*i);
    return x;
}
bool ExactTextInOwnedStack(const uint8_t* mem,uint64_t base,uint64_t length,
                           uint64_t pointer,const char* value) {
    if(!mem||!value||pointer<base||pointer>=base+length)return false;
    const size_t offset=static_cast<size_t>(pointer-base);
    const size_t bytes=std::strlen(value)+1;
    return bytes<=length-offset &&
           std::memcmp(mem+offset,value,bytes)==0;
}
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 3;
    kernix::g2e::GuestPreflight pinned{};
    std::string error;
    const bool valid=kernix::g2e::Validate(fd,pinned,error);
    assert(::close(fd)==0);
    assert(valid && error=="none" && pinned.exactSha256Matched &&
           pinned.readOnlyAnonymousSnapshots &&
           pinned.exactInterpreterAndGlibcClosure &&
           !pinned.guestCodeExecuted && !pinned.dynamicLinkerExecuted);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)entropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::GuestLdsoEntryWitness witness{};
    kernix::g2b::X86GuestProcessLaunchPlan originalPlan{};
    assert(kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
       pinned,entropy,witness,error,&originalPlan));
    assert(witness.exactOriginalSha256Assets &&
           witness.guestPtInterpEntryContractVerified &&
           witness.linuxX86AuxvContractVerified);
    kernix::g0::OwnedRealOriginalGuestStartupStack owned{};
    assert(owned.Install(pinned,entropy,error));
    assert(error=="none" && owned.Installed());
    const long nativePage=::sysconf(_SC_PAGESIZE);
    assert(nativePage==4096 || nativePage==16384);
    assert(owned.NativeGuardBytes()==static_cast<size_t>(nativePage));
    assert(owned.GuestStackBytes()==65536);
    assert(owned.RealGuestRSP()%16==0);
    assert(owned.RealGuestRSP()>=owned.RealGuestStackBase());
    assert(owned.RealGuestRSP()<
           owned.RealGuestStackBase()+owned.GuestStackBytes());
    assert(!owned.OriginalLdsoMapped() && !owned.FEXGuestEntryExecuted());

    const uint8_t* data=owned.ViewOwnedGuestStack();
    assert(data!=nullptr);
    const uint64_t base=owned.RealGuestStackBase();
    const auto size=static_cast<size_t>(owned.GuestStackBytes());
    const auto wordBase=static_cast<size_t>(owned.RealGuestRSP()-base);
    assert(LoadLE(data,wordBase,size)==1);
    const uint64_t argv0=LoadLE(data,wordBase+8,size);
    assert(ExactTextInOwnedStack(data,base,size,argv0,
                                 "/bin/kernix-g2e-dynamic-guest"));
    assert(LoadLE(data,wordBase+16,size)==0);
    const uint64_t env0=LoadLE(data,wordBase+24,size);
    assert(ExactTextInOwnedStack(data,base,size,env0,"LANG=C"));
    assert(LoadLE(data,wordBase+32,size)==0);
    const uint64_t auxBase=wordBase+40;
    constexpr std::array<uint64_t,14> tags{
      3,4,5,6,7,8,9,11,12,13,14,23,25,31
    };
    size_t rnd=0,fn=0;
    for(size_t i=0;i<tags.size();++i) {
        const uint64_t tag=LoadLE(data,auxBase+i*16,size);
        const uint64_t value=LoadLE(data,auxBase+i*16+8,size);
        assert(tag==tags[i]);
        if(tag==3)assert(value==originalPlan.guestMainPHDR);
        if(tag==7)assert(value==originalPlan.interpreterLoadBias);
        if(tag==9)assert(value==originalPlan.guestMainEntry);
        if(tag==25){
            assert(value>=base && value+16<=base+size);
            assert(std::memcmp(data+(value-base),entropy.data(),16)==0);
            ++rnd;
        }
        if(tag==31){assert(value==argv0);++fn;}
    }
    assert(rnd==1 && fn==1);
    assert(LoadLE(data,auxBase+14*16,size)==0);
    assert(LoadLE(data,auxBase+14*16+8,size)==0);
    // The original source-only 64KiB stack remains untouched: only
    // returned owner-mapped guest pointers are rebased to an actual VMA.
    assert(originalPlan.stack.guestRSP!=owned.RealGuestRSP());
    assert(originalPlan.stack.guestExecFnPointer!=argv0);
    assert(originalPlan.stack.guestRandomPointer<base ||
           originalPlan.stack.guestRandomPointer>=base+size);

    // Failing preflight and zero-entropy inputs must never install an
    // unauthenticated guest stack. A valid previous mapping is released.
    pinned.exactInterpreterAndGlibcClosure=false;
    assert(!owned.Install(pinned,entropy,error));
    assert(!owned.Installed() && owned.RealGuestRSP()==0);
    pinned.exactInterpreterAndGlibcClosure=true;
    std::array<uint8_t,16> zeroEntropy{};
    assert(!owned.Install(pinned,zeroEntropy,error));
    assert(!owned.Installed());
    assert(owned.Install(pinned,entropy,error));
    assert(owned.Reset() && !owned.Installed());

    std::puts("KERNIX_G0_SOURCE_SHA256_ORIGINAL_LDSO_AUXV_KERNEL_GUARDED_REAL_GUEST_STACK_HOST_PASS_NO_FEX_ANDROID");
    return 0;
}
