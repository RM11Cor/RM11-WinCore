#include "kernix_guest_linux_x86_initial_stack.h"
#include <elf.h>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>

namespace {
uint64_t wordAt(const kernix::g2b::LinuxX86StackImage& img, uint64_t a) {
    assert(a>=img.guestBottom && a<=img.guestTop-8);
    uint64_t v=0;
    for(unsigned i=0;i<8;i++) {
        size_t o=static_cast<size_t>(a-img.guestBottom+i);
        v|=static_cast<uint64_t>(img.bytes[o])<<(i*8);
    }
    return v;
}
bool stringAt(const kernix::g2b::LinuxX86StackImage& img,
              uint64_t a, const char* expected) {
    const size_t n=strlen(expected)+1;
    if(a<img.guestBottom || a>img.guestTop ||
       n>img.guestTop-a) return false;
    return memcmp(img.bytes.data()+static_cast<size_t>(a-img.guestBottom),
                  expected,n)==0;
}
void shouldFail(const kernix::g2b::LinuxX86StackInput& in) {
    kernix::g2b::LinuxX86StackImage img;
    std::string error;
    assert(!kernix::g2b::PrepareLinuxX86InitialStack(in,img,error));
    assert(error!="none" && !error.empty());
    assert(!img.initialStackLayoutValidated && img.bytes.empty());
    assert(!img.guestCodeExecuted && !img.guestMemoryMapped);
}
}
int main(int argc, char** argv) {
    if(argc!=2) return 2;
    int fd=open(argv[1],O_RDONLY|O_CLOEXEC);
    assert(fd>=0);
    Elf64_Ehdr e{};
    assert(pread(fd,&e,sizeof(e),0)==sizeof(e));
    assert(memcmp(e.e_ident,ELFMAG,SELFMAG)==0 &&
           e.e_ident[EI_CLASS]==ELFCLASS64 && e.e_machine==EM_X86_64);
    assert(e.e_type==ET_DYN && e.e_phnum>0 && e.e_phnum<=128);
    assert(e.e_phentsize==sizeof(Elf64_Phdr));
    uint64_t phdrAddr=0;
    for (unsigned i=0;i<e.e_phnum;i++) {
        Elf64_Phdr p{};
        const off_t off=static_cast<off_t>(e.e_phoff)+
            static_cast<off_t>(i*sizeof(p));
        assert(pread(fd,&p,sizeof(p),off)==sizeof(p));
        if(p.p_type==PT_PHDR) phdrAddr=p.p_vaddr;
    }
    close(fd);
    assert(phdrAddr>0);
    constexpr uint64_t loadBias=0x0000555500000000ULL;
    kernix::g2b::LinuxX86StackInput in{};
    in.guestStackBottom=0x00007fff10000000ULL;
    in.guestStackBytes=64*1024;
    in.guestPageBytes=4096;
    in.guestMainProgramHeaders=loadBias+phdrAddr;
    in.guestMainEntry=loadBias+e.e_entry;
    in.guestInterpreterBase=0x0000711100000000ULL;
    in.programHeaderCount=e.e_phnum;
    in.uid=static_cast<uint32_t>(getuid());
    in.euid=static_cast<uint32_t>(geteuid());
    in.gid=static_cast<uint32_t>(getgid());
    in.egid=static_cast<uint32_t>(getegid());
    // Deterministic CI fixture only. Production MUST supply entropy.
    for(size_t i=0;i<in.randomBytes.size();i++)
        in.randomBytes[i]=static_cast<uint8_t>(i+1);
    in.args={"/bin/kernix-fixture","--bounded"};
    in.environment={"LANG=C","KERNIX_G2B=1"};
    kernix::g2b::LinuxX86StackImage out;
    std::string reason;
    assert(kernix::g2b::PrepareLinuxX86InitialStack(in,out,reason));
    assert(reason=="none" && out.initialStackLayoutValidated);
    assert(out.guestRSP%16==0 && out.guestTop==in.guestStackBottom+in.guestStackBytes);
    assert(out.bytes.size()==in.guestStackBytes &&
           !out.guestCodeExecuted && !out.guestMemoryMapped &&
           !out.androidWineTested);
    uint64_t cursor=out.guestRSP;
    assert(wordAt(out,cursor)==in.args.size());cursor+=8;
    for(const auto& name:in.args) {
        assert(stringAt(out,wordAt(out,cursor),name.c_str()));
        cursor+=8;
    }
    assert(wordAt(out,cursor)==0);cursor+=8;
    for(const auto& name:in.environment) {
        assert(stringAt(out,wordAt(out,cursor),name.c_str()));
        cursor+=8;
    }
    assert(wordAt(out,cursor)==0);cursor+=8;
    std::vector<std::pair<uint64_t,uint64_t>> aux;
    for(size_t i=0;i<out.auxEntryCount;i++) {
        const uint64_t type=wordAt(out,cursor);cursor+=8;
        const uint64_t val=wordAt(out,cursor);cursor+=8;
        aux.emplace_back(type,val);
    }
    assert(wordAt(out,cursor)==0);cursor+=8;
    assert(wordAt(out,cursor)==0);cursor+=8;
    assert(cursor<=out.guestRandomPointer);
    auto value=[&](uint64_t type) {
        for(auto [key,val]:aux) if(key==type) return val;
        assert(false && "AUXV tag missing");return uint64_t{0};
    };
    assert(out.auxEntryCount==14);
    assert(value(3)==in.guestMainProgramHeaders);
    assert(value(4)==sizeof(Elf64_Phdr));
    assert(value(5)==e.e_phnum);
    assert(value(6)==4096);
    assert(value(7)==in.guestInterpreterBase);
    assert(value(9)==in.guestMainEntry);
    assert(value(11)==in.uid && value(12)==in.euid);
    assert(value(13)==in.gid && value(14)==in.egid);
    assert(value(23)==0 && value(25)==out.guestRandomPointer &&
           value(31)==out.guestExecFnPointer);
    assert(stringAt(out,value(31),in.args[0].c_str()));
    assert(memcmp(out.bytes.data()+static_cast<size_t>(
                  value(25)-out.guestBottom),in.randomBytes.data(),16)==0);
    // Negative cases must be fail-closed, never leave old successful bytes.
    in.randomBytes.fill(0);shouldFail(in);
    in.randomBytes[0]=10;
    in.guestStackBytes=4095;shouldFail(in);in.guestStackBytes=65536;
    in.guestStackBottom=0;shouldFail(in);
    in.guestStackBottom=0x00007fff10000000ULL;
    in.guestMainEntry=0;shouldFail(in);in.guestMainEntry=loadBias+e.e_entry;
    in.guestMainProgramHeaders=0;shouldFail(in);
    in.guestMainProgramHeaders=loadBias+phdrAddr;
    in.guestInterpreterBase=0;shouldFail(in);
    in.guestInterpreterBase=0x0000711100000000ULL;
    in.programHeaderCount=0;shouldFail(in);in.programHeaderCount=e.e_phnum;
    in.guestPageBytes=12345;shouldFail(in);in.guestPageBytes=16384;
    assert(kernix::g2b::PrepareLinuxX86InitialStack(in,out,reason));
    assert(out.initialStackLayoutValidated && out.guestRSP%16==0);
    // The second layout's AT_PAGESZ word is checked in-place below.
    uint64_t second = out.guestRSP + 8 + (in.args.size()+1)*8 + (in.environment.size()+1)*8;
    assert(wordAt(out,second+3*16)==6 && wordAt(out,second+3*16+8)==16384);
    in.guestPageBytes=4096;
    in.environment={"UNSAFE_ENV"};shouldFail(in);
    in.environment={"LANG=C"};
    in.args[0]=std::string("evil\nname");shouldFail(in);
    in.args[0]="/bin/kernix-fixture";
    in.args.clear();shouldFail(in);
    in.args={"/bin/kernix-fixture"};
    in.guestStackBottom=0x00007ffffffff000ULL;shouldFail(in);
    puts("KERNIX_G2B_REAL_ELF_X86_LINUX_STACK_ARGV_ENVP_AUXV_ABI_PASS_NOT_FEX_EXECUTION");
    return 0;
}
