#pragma once
// KERNIX G2-D: *one* real, fixed MIT x86-64 imported function.
// Three immutable O_NOFOLLOW SHA-pinned guest ELFs; exact ELF64 PLT/RELA
// metadata and provider export; no arbitrary guest loader, glibc, PE,
// arbitrary symbols or syscalls. Signed Android v0.22 is NOT modified.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_mit_owned_guest_snapshots.h"
#include <elf.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <sys/mman.h>

namespace kernix::g2d {

inline constexpr const char* kMain="/bin/kernix-g2d-import-app";
inline constexpr const char* kProvider=
    "/lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1";
inline constexpr const char* kInterp=
    "/lib64/ld-kernix-g2d-mit-import-test.so.1";
inline constexpr const char* kSymbol="kernix_g2d_imported_value";
inline constexpr const char* kSoname="libkernix-g2d-mit-import.so.1";
inline constexpr uint64_t kRax=0x4b45524e49584731ULL;
inline constexpr std::array<uint64_t,3> kBytes{{50504,50048,50024}};
inline constexpr std::array<const char*,3> kSha{{
    "a29be66289673e80cef5de115dfce0f05cb04599368f039c44c728ad0b2278a0",
    "8ec9bac9b3a21eeaedb4ec9c7071907a6074cbea9eb41f78591e176f0a27441e",
    "a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2"
}};
inline constexpr std::array<std::string_view,3> kPaths{{kMain,kProvider,kInterp}};

struct PinnedImportELFs {
    std::array<kernix::g2c::ReadonlyGuestSnapshot,3> files;
    bool verified=false;
    void reset() noexcept {
        for(auto& file:files) file.reset();
        verified=false;
    }
};
inline bool PinFixedImportELFs(const char* appFiles,
                               PinnedImportELFs& out,std::string& why) {
    out.reset();
    if (!appFiles || appFiles[0]!='/' || std::strlen(appFiles)>1024) {
        why="G2D_BAD_APP_PRIVATE_ROOT";return false;
    }
    using kernix::g2c::OwnedFd;
    using kernix::g2c::OpenDirectory;
    OwnedFd root(open(appFiles,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    struct stat statinfo{};
    if(root.get()<0 || fstat(root.get(),&statinfo) || statinfo.st_uid!=getuid()) {
        why="G2D_APP_PRIVATE_ROOT_REJECTED";return false;
    }
    OwnedFd k(OpenDirectory(root.get(),"kernix"));
    OwnedFd rt(OpenDirectory(k.get(),"runtime-v1"));
    OwnedFd gr(OpenDirectory(rt.get(),"guest-rootfs"));
    OwnedFd fixed(OpenDirectory(gr.get(),"g2d-import-v1"));
    OwnedFd bin(OpenDirectory(fixed.get(),"bin"));
    OwnedFd lib(OpenDirectory(fixed.get(),"lib"));
    OwnedFd libx(OpenDirectory(lib.get(),"x86_64-linux-gnu"));
    OwnedFd lib64(OpenDirectory(fixed.get(),"lib64"));
    if(fixed.get()<0 || bin.get()<0 || libx.get()<0 || lib64.get()<0){
        why="G2D_GUEST_FIXED_DIR_OR_SYMLINK_REJECTED";return false;
    }
    const std::array<int,3> parents{{bin.get(),libx.get(),lib64.get()}};
    const std::array<const char*,3> names{{
        "kernix-g2d-import-app","libkernix-g2d-mit-import.so.1",
        "ld-kernix-g2d-mit-import-test.so.1"
    }};
    for(size_t i=0;i<3;i++){
        OwnedFd fd(openat(parents[i],names[i],
             O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        if(!kernix::g2c::VerifyFile(fd.get(),kBytes[i],kSha[i]) ||
           !out.files[i].Capture(fd.get(),kBytes[i],kSha[i],why)) {
            out.reset();why="G2D_GUEST_ELF_SHA256_UID_MODE_OR_SNAPSHOT_REJECTED";
            return false;
        }
    }
    out.verified=true;why="none";return true;
}
inline bool FetchFrozenELF(const PinnedImportELFs& set,std::string_view path,
                           std::vector<unsigned char>& content) {
    content.clear();
    if(!set.verified)return false;
    for(size_t i=0;i<3;i++){
        if(path!=kPaths[i])continue;
        const auto& f=set.files[i];
        if(!f.readOnlySnapshot() || f.size()!=kBytes[i])return false;
        content.assign(f.bytes(),f.bytes()+f.size());
        return true;
    }
    return false;
}
inline kernix::g2b::GuestELFBytesResolver Resolver(const PinnedImportELFs& set) {
    return [&set](std::string_view path,std::vector<unsigned char>& out){
        return FetchFrozenELF(set,path,out);
    };
}
struct FixedImportPlan {
    uint64_t mainGotVaddr=0;
    uint64_t exportedFunctionVaddr=0;
    bool exactOneJumpSlot=false;
};
template<class T>
inline bool ReadStruct(std::span<const unsigned char> b,uint64_t off,T& out) {
    if(off>b.size() || sizeof(T)>b.size()-static_cast<size_t>(off))return false;
    std::memcpy(&out,b.data()+static_cast<size_t>(off),sizeof(T));return true;
}
inline bool ElfIdentity(std::span<const unsigned char> b,Elf64_Ehdr& h,
                        std::vector<Elf64_Phdr>& ph) {
    if(!ReadStruct(b,0,h) || b.size()>256*1024 ||
       std::memcmp(h.e_ident,ELFMAG,SELFMAG)!=0 ||
       h.e_ident[EI_CLASS]!=ELFCLASS64 ||
       h.e_ident[EI_DATA]!=ELFDATA2LSB ||
       h.e_type!=ET_DYN || h.e_machine!=EM_X86_64 ||
       h.e_version!=EV_CURRENT ||
       h.e_phentsize!=sizeof(Elf64_Phdr) ||
       h.e_phnum<2 || h.e_phnum>24 ||
       h.e_phoff>b.size() ||
       static_cast<size_t>(h.e_phnum)> (b.size()-h.e_phoff)/sizeof(Elf64_Phdr))
        return false;
    ph.clear();
    for(unsigned i=0;i<h.e_phnum;i++){
        Elf64_Phdr p{};
        if(!ReadStruct(b,h.e_phoff+i*sizeof p,p))return false;
        if(p.p_type==PT_LOAD && p.p_memsz){
            if(p.p_filesz>p.p_memsz || p.p_offset>b.size() ||
               p.p_filesz>b.size()-p.p_offset ||
               p.p_align<16384 || (p.p_align&(p.p_align-1)) ||
               (p.p_vaddr-p.p_offset)%16384 ||
               p.p_vaddr>UINT64_MAX-p.p_memsz ||
               ((p.p_flags&PF_W) && (p.p_flags&PF_X)))
                return false;
        }
        ph.push_back(p);
    }
    return true;
}
inline bool FileVaddr(std::span<const unsigned char> b,
                      const std::vector<Elf64_Phdr>& ph,
                      uint64_t vaddr,uint64_t length,
                      uint64_t& offset,int requireFlags=0) {
    if(length>65536 || vaddr>UINT64_MAX-length)return false;
    unsigned found=0;uint64_t at=0;
    for(const auto& p:ph){
        if(p.p_type!=PT_LOAD || (p.p_flags&requireFlags)!=static_cast<unsigned>(requireFlags) ||
           vaddr<p.p_vaddr || vaddr-p.p_vaddr>p.p_filesz ||
           length>p.p_filesz-(vaddr-p.p_vaddr))continue;
        at=p.p_offset+(vaddr-p.p_vaddr);
        if(at>b.size() || length>b.size()-at)return false;
        ++found;
    }
    if(found!=1)return false;
    offset=at;return true;
}
inline bool Dynamic(std::span<const unsigned char> raw,
                    const std::vector<Elf64_Phdr>& ph,
                    std::vector<Elf64_Dyn>& values) {
    values.clear();unsigned found=0;
    for(const auto& p:ph){
        if(p.p_type!=PT_DYNAMIC)continue;
        if(++found!=1 || p.p_filesz>2048 ||
           p.p_filesz%sizeof(Elf64_Dyn) ||
           p.p_offset>raw.size() || p.p_filesz>raw.size()-p.p_offset)
            return false;
        bool ended=false;
        for(uint64_t n=0;n<p.p_filesz/sizeof(Elf64_Dyn);n++){
            Elf64_Dyn d{};
            if(!ReadStruct(raw,p.p_offset+n*sizeof d,d))return false;
            if(d.d_tag==DT_NULL){ended=true;break;}
            values.push_back(d);
        }
        if(!ended)return false;
    }
    return found==1;
}
inline bool OneTag(const std::vector<Elf64_Dyn>& d,int64_t tag,uint64_t& val) {
    unsigned n=0;
    for(const auto& x:d)if(x.d_tag==tag){val=x.d_un.d_val;n++;}
    return n==1;
}
inline bool SymbolName(std::span<const unsigned char> raw,
                       const std::vector<Elf64_Phdr>& ph,
                       const std::vector<Elf64_Dyn>& dyn,
                       uint32_t index,std::string_view expected) {
    uint64_t start=0,len=0,off=0;
    if(!OneTag(dyn,DT_STRTAB,start) || !OneTag(dyn,DT_STRSZ,len) ||
       len>4096 || index>=len ||
       !FileVaddr(raw,ph,start+index,len-index,off))return false;
    const auto* str=reinterpret_cast<const char*>(raw.data()+off);
    const void* end=std::memchr(str,0,len-index);
    return end && std::string_view(str,
              static_cast<const char*>(end)-str)==expected;
}
inline bool ImportedSymbol(std::span<const unsigned char> raw,
                           const std::vector<Elf64_Phdr>& ph,
                           const std::vector<Elf64_Dyn>& d,
                           uint32_t index,Elf64_Sym& sym) {
    uint64_t addr=0,ent=0,off=0;
    if(index!=1 || !OneTag(d,DT_SYMTAB,addr) ||
       !OneTag(d,DT_SYMENT,ent) || ent!=sizeof(Elf64_Sym) ||
       addr>UINT64_MAX-index*ent ||
       !FileVaddr(raw,ph,addr+index*ent,sizeof sym,off) ||
       !ReadStruct(raw,off,sym) ||
       !SymbolName(raw,ph,d,sym.st_name,kSymbol) ||
       ELF64_ST_BIND(sym.st_info)!=STB_GLOBAL)
        return false;
    return true;
}
inline bool AuditFixedImport(const PinnedImportELFs& s,FixedImportPlan& plan,
                             std::string& reason) {
    plan={};
    if(!s.verified){reason="G2D_SOURCE_NOT_FROZEN";return false;}
    const std::span<const unsigned char> main(s.files[0].bytes(),s.files[0].size());
    const std::span<const unsigned char> provider(s.files[1].bytes(),s.files[1].size());
    Elf64_Ehdr mh{},dh{};std::vector<Elf64_Phdr> mp,dp;
    std::vector<Elf64_Dyn> md,dd;
    if(!ElfIdentity(main,mh,mp) || !ElfIdentity(provider,dh,dp) ||
       !Dynamic(main,mp,md) || !Dynamic(provider,dp,dd)){
        reason="G2D_ELF_DYNAMIC_IDENTITY_REJECTED";return false;
    }
    uint64_t needed=0,soname=0,jmprel=0,relsz=0,pltrel=0,roff=0;
    if(!OneTag(md,DT_NEEDED,needed) ||
       !SymbolName(main,mp,md,static_cast<uint32_t>(needed),kSoname) ||
       !OneTag(dd,DT_SONAME,soname) ||
       !SymbolName(provider,dp,dd,static_cast<uint32_t>(soname),kSoname) ||
       !OneTag(md,DT_JMPREL,jmprel) ||
       !OneTag(md,DT_PLTRELSZ,relsz) ||
       !OneTag(md,DT_PLTREL,pltrel) ||
       relsz!=sizeof(Elf64_Rela) || pltrel!=DT_RELA ||
       !FileVaddr(main,mp,jmprel,relsz,roff)){
        reason="G2D_ONE_REAL_PLT_RELOCATION_MISSING";return false;
    }
    for(const auto& entry:md){
        if(entry.d_tag==DT_RELA || entry.d_tag==DT_REL){
            reason="G2D_UNSUPPORTED_EXTRA_RELOCATION";return false;
        }
    }
    Elf64_Rela rela{};
    Elf64_Sym import{},exported{};
    if(!ReadStruct(main,roff,rela) ||
       ELF64_R_TYPE(rela.r_info)!=R_X86_64_JUMP_SLOT ||
       ELF64_R_SYM(rela.r_info)!=1 || rela.r_addend!=0 ||
       !ImportedSymbol(main,mp,md,1,import) ||
       import.st_shndx!=SHN_UNDEF ||
       !ImportedSymbol(provider,dp,dd,1,exported) ||
       exported.st_shndx==SHN_UNDEF ||
       ELF64_ST_TYPE(exported.st_info)!=STT_FUNC ||
       exported.st_size!=11 ||
       rela.r_offset!=0xc000 || exported.st_value!=0x4000){
        reason="G2D_RELATIONSHIP_BETWEEN_PLT_SYMBOL_AND_EXPORT_REJECTED";return false;
    }
    uint64_t gotOff=0,fnOff=0;
    if(!FileVaddr(main,mp,rela.r_offset,sizeof(uint64_t),gotOff,PF_W) ||
       !FileVaddr(provider,dp,exported.st_value,11,fnOff,PF_X)){
        reason="G2D_GOT_OR_EXTERNAL_FUNCTION_NOT_IN_OWN_PTLOAD";return false;
    }
    const std::array<unsigned char,11> expectedCode{{
       0x48,0xb8,0x20,0x47,0x58,0x49,0x4e,0x52,0x45,0x4b,0xc3
    }};
    if(std::memcmp(provider.data()+fnOff,expectedCode.data(),11)!=0){
        reason="G2D_UNRECOGNIZED_EXTERNAL_FUNCTION_BYTES";return false;
    }
    plan.mainGotVaddr=rela.r_offset;
    plan.exportedFunctionVaddr=exported.st_value;
    plan.exactOneJumpSlot=true;reason="none";
    return true;
}

// This applies exactly ONE audited imported x86 function address to
// a non-executable RW GOT page, then restores page to PROT_READ.
// It is NOT an arbitrary Linux dynamic linker or relocation engine.
inline bool WriteOneVerifiedGuestJumpSlot(
    const FixedImportPlan& plan,uint64_t mainBias,uint64_t providerBias,
    const kernix::g2b::X86HostNoAccessReservation& mainWindow,
    const kernix::g2b::X86HostNoAccessReservation& providerWindow,
    std::string& why) {
    if(!plan.exactOneJumpSlot ||
       mainBias>UINT64_MAX-plan.mainGotVaddr ||
       providerBias>UINT64_MAX-plan.exportedFunctionVaddr){
        why="G2D_BAD_BOUND_RELOCATION_PLAN";return false;
    }
    const uint64_t got=mainBias+plan.mainGotVaddr;
    const uint64_t function=providerBias+plan.exportedFunctionVaddr;
    const long hostPage=sysconf(_SC_PAGESIZE);
    if((hostPage!=4096 && hostPage!=16384) ||
       got<mainWindow.guestStart ||
       got-mainWindow.guestStart>mainWindow.guestBytes-8 ||
       function<providerWindow.guestStart ||
       function-providerWindow.guestStart>=providerWindow.guestBytes){
        why="G2D_IMPORT_GOT_OR_FUNCTION_OUTSIDE_RESERVED_GUEST_VA";return false;
    }
    const uint64_t mask=static_cast<uint64_t>(hostPage)-1;
    const uint64_t start=got&~mask;
    if(start<mainWindow.guestStart ||
       static_cast<uint64_t>(hostPage)>mainWindow.guestBytes ||
       start-mainWindow.guestStart>
       mainWindow.guestBytes-static_cast<uint64_t>(hostPage) ||
       (got+8>start+static_cast<uint64_t>(hostPage))) {
        why="G2D_RELOCATION_CROSSES_OR_ESCAPES_HOST_PAGE";return false;
    }
    void* page=reinterpret_cast<void*>(static_cast<uintptr_t>(start));
    if(mprotect(page,static_cast<size_t>(hostPage),PROT_READ|PROT_WRITE)!=0){
        why="G2D_GOT_PROT_READ_WRITE_TRANSITION_FAILED";return false;
    }
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(got)),
                &function,sizeof function);
    if(mprotect(page,static_cast<size_t>(hostPage),PROT_READ)!=0){
        why="G2D_GOT_RESTORE_READONLY_FAILED";return false;
    }
    uint64_t readback=0;
    std::memcpy(&readback,
        reinterpret_cast<const void*>(static_cast<uintptr_t>(got)),8);
    if(readback!=function){why="G2D_GOT_RELOCATION_POSTWRITE_CHECK_FAILED";return false;}
    why="none";return true;
}
} // namespace kernix::g2d
