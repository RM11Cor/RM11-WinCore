#pragma once
// SPDX-License-Identifier: MIT
// G0 real kernel-selected, guard-protected Linux x86-64 initial stack
// from the exact source-SHA256 original GNU main / ld-linux / libc.
// Non-executing runtime handoff: original guest PT_LOAD not mapped here,
// no FEX RIP or FS/TLS, no relocations, no glibc or Wine.
#include "kernix_g2e_guest_ldso_entry_contract.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix::g0 {
class OwnedRealOriginalGuestStartupStack final {
public:
    OwnedRealOriginalGuestStartupStack()=default;
    ~OwnedRealOriginalGuestStartupStack(){Reset();}
    OwnedRealOriginalGuestStartupStack(const OwnedRealOriginalGuestStartupStack&)=delete;
    OwnedRealOriginalGuestStartupStack& operator=(const OwnedRealOriginalGuestStartupStack&)=delete;
    bool Reset() noexcept {
        bool ok=true;
        if(mapping_) ok=(::munmap(mapping_,mappingBytes_)==0);
        mapping_=nullptr;mappingBytes_=0;stackBase_=0;stackBytes_=0;
        rsp_=0;guardBytes_=0;sourcePinned_=false;
        return ok;
    }
    bool Install(const kernix::g2e::GuestPreflight& source,
                 const std::array<uint8_t,16>& entropy,
                 std::string& reason) {
        Reset();
        kernix::g2e::GuestLdsoEntryWitness attestation{};
        kernix::g2b::X86GuestProcessLaunchPlan planned{};
        if(!kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
                source,entropy,attestation,reason,&planned) ||
           !attestation.exactOriginalSha256Assets ||
           !attestation.guestPtInterpEntryContractVerified ||
           !attestation.linuxX86AuxvContractVerified ||
           planned.guestMemoryMapped || planned.guestCodeExecuted ||
           planned.dynamicLinkerExecuted || planned.fexEntryPointAssigned ||
           planned.stack.bytes.size()!=kernix::g2e::kC0StackBytes) {
            reason="G0_NO_ORIGINAL_SOURCE_PINNED_LDSO_AUXV_PLAN";
            return false;
        }
        const auto& s=planned.stack;
        const uint64_t oldBase=s.guestBottom;
        const uint64_t oldTop=s.guestTop;
        if(s.guestRSP<oldBase || s.guestRSP>=oldTop ||
           s.guestRSP%16 || s.guestTop-s.guestBottom!=s.bytes.size())
            return fail("G0_STACK_SOURCE_POINTERS_BAD",reason);
        const long page=::sysconf(_SC_PAGESIZE);
        if(page!=4096 && page!=16384)
            return fail("G0_UNSUPPORTED_NATIVE_PAGE_SIZE",reason);
        const size_t guard=static_cast<size_t>(page);
        const size_t length=s.bytes.size();
        if(length>std::numeric_limits<size_t>::max()-guard)
            return fail("G0_GUEST_STACK_CAPACITY_OVERFLOW",reason);
        const size_t total=guard+length;
        // This is an advisory x86-canonical address hint, NOT MAP_FIXED.
        // The kernel chooses the final VMA and we validate the result.
        void* raw=::mmap(reinterpret_cast<void*>(0x0000600000000000ULL),
                         total,PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(raw==MAP_FAILED)return fail("G0_KERNEL_GUEST_STACK_MMAP_FAILED",reason);
        mapping_=raw;mappingBytes_=total;
        const uint64_t address=reinterpret_cast<uintptr_t>(raw);
        if(address>=kernix::g2b::kLinuxGuestUserLimit ||
           total>=kernix::g2b::kLinuxGuestUserLimit-address ||
           !kernix::g2b::ValidLinuxGuestPointer(address+guard))
            return fail("G0_NATIVE_STACK_OUTSIDE_X86_USER_CANONICAL_RANGE",reason);
        if(::mprotect(raw,guard,PROT_NONE)!=0)
            return fail("G0_NATIVE_STACK_GUARD_MPROTECT_FAILED",reason);
        stackBase_=address+guard;
        stackBytes_=length;
        guardBytes_=guard;
        rsp_=stackBase_+(s.guestRSP-oldBase);
        if(rsp_%16 || rsp_<stackBase_ || rsp_>=stackBase_+length)
            return fail("G0_GUEST_RUNTIME_RSP_INVALID",reason);
        // Verify that the kernel-selected host/guest VMA does not collide
        // with the original ELF *planned* regions, prior to FEX handoff.
        for(const auto& region:planned.regions) {
            if(region.isGuestStack)continue;
            if(!(stackBase_+length<=region.first ||
                 region.pastLast<=stackBase_))
                return fail("G0_REAL_STACK_OVERLAPS_SOURCE_ELF_PLAN",reason);
        }
        std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(stackBase_)),
                    s.bytes.data(),length);
        // Rebase only stack-owned string and random-byte addresses.
        // AT_PHDR, AT_BASE, AT_ENTRY intentionally remain the original
        // verified ELF *plan addresses* and are NOT live executable VMAs.
        const size_t rspOffset=static_cast<size_t>(s.guestRSP-oldBase);
        const size_t encodedWords=5+14*2+2;
        if(rspOffset>length || encodedWords> (length-rspOffset)/8)
            return fail("G0_STACK_WORD_TABLE_TRUNCATED",reason);
        if(load(rspOffset)!=1 || load(rspOffset+16)!=0 ||
           load(rspOffset+32)!=0)
            return fail("G0_LINUX_STACK_ARG_ENV_COUNT_INVALID",reason);
        if(!patch(rspOffset+8,oldBase,oldTop,s.guestExecFnPointer) ||
           !patch(rspOffset+24,oldBase,oldTop,0))
            return fail("G0_LINUX_STACK_ARG_ENV_REBASE_FAILED",reason);
        const size_t auxBegin=rspOffset+40;
        bool foundRandom=false,foundExecfn=false;
        for(size_t i=0;i<14;++i){
            const size_t at=auxBegin+i*16;
            const uint64_t tag=load(at),value=load(at+8);
            if(tag==25){
                if(foundRandom || value!=s.guestRandomPointer ||
                   !patch(at+8,oldBase,oldTop,value))
                    return fail("G0_LINUX_STACK_AT_RANDOM_REBASE_FAILED",reason);
                foundRandom=true;
            } else if(tag==31){
                if(foundExecfn || value!=s.guestExecFnPointer ||
                   !patch(at+8,oldBase,oldTop,value))
                    return fail("G0_LINUX_STACK_AT_EXECFN_REBASE_FAILED",reason);
                foundExecfn=true;
            }
        }
        if(!foundRandom || !foundExecfn ||
           load(auxBegin+14*16)!=0 || load(auxBegin+14*16+8)!=0)
            return fail("G0_GUEST_AUXV_TERMINATOR_REJECTED",reason);
        // Verify that original ASLR-independent ELF tags weren't rebased
        // accidentally and no writable/executable overlap was requested.
        if(load(auxBegin+0*16)!=3 ||
           load(auxBegin+0*16+8)!=planned.guestMainPHDR ||
           load(auxBegin+4*16)!=7 ||
           load(auxBegin+4*16+8)!=planned.interpreterLoadBias ||
           load(auxBegin+6*16)!=9 ||
           load(auxBegin+6*16+8)!=planned.guestMainEntry)
            return fail("G0_ELF_AUXV_METADATA_CHANGED_UNEXPECTEDLY",reason);
        sourcePinned_=true;
        reason="none";
        return true;
    }
    bool Installed() const noexcept {return sourcePinned_ && mapping_!=nullptr;}
    uint64_t RealGuestRSP() const noexcept {return Installed()?rsp_:0;}
    uint64_t RealGuestStackBase() const noexcept {return Installed()?stackBase_:0;}
    uint64_t GuestStackBytes() const noexcept {return Installed()?stackBytes_:0;}
    size_t NativeGuardBytes() const noexcept {return Installed()?guardBytes_:0;}
    bool OriginalLdsoMapped() const noexcept {return false;}
    bool FEXGuestEntryExecuted() const noexcept {return false;}
    // This pointer only exposes the **owned guarded RW guest stack**.
    const uint8_t* ViewOwnedGuestStack() const noexcept {
        return Installed()?reinterpret_cast<const uint8_t*>(
          static_cast<uintptr_t>(stackBase_)):nullptr;
    }
private:
    void* mapping_=nullptr;
    size_t mappingBytes_=0;
    uint64_t stackBase_=0,rsp_=0;
    uint64_t stackBytes_=0;
    size_t guardBytes_=0;
    bool sourcePinned_=false;
    bool fail(const char* msg,std::string& reason) {
        Reset();reason=msg;return false;
    }
    uint64_t load(size_t off) const noexcept {
        const auto* p=reinterpret_cast<const uint8_t*>(
          static_cast<uintptr_t>(stackBase_));
        uint64_t out=0;
        for(unsigned i=0;i<8;++i)out|=uint64_t(p[off+i])<<(8*i);
        return out;
    }
    void store(size_t off,uint64_t v) noexcept {
        auto* p=reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(stackBase_));
        for(unsigned i=0;i<8;++i)p[off+i]=static_cast<uint8_t>(v>>(8*i));
    }
    bool patch(size_t off,uint64_t originalBottom,uint64_t originalTop,
               uint64_t expected) noexcept {
        const uint64_t old=load(off);
        if(old<originalBottom || old>=originalTop ||
           (expected!=0 && old!=expected) ||
           old-originalBottom>=stackBytes_)return false;
        store(off,stackBase_+(old-originalBottom));
        return true;
    }
};
} // namespace kernix::g0
