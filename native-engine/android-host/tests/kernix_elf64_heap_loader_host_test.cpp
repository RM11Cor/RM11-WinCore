// KERNIX host regression: load only compiled bounded ELF64 heap-syscall fixture.
// SPDX-License-Identifier: MIT
#include "kernix_elf64_loader.h"
#include "kernix_guest_memory_syscalls.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if(argc!=2) return 1;
    std::ifstream source(argv[1],std::ios::binary);
    if(!source) return 2;
    std::vector<unsigned char> elf(std::istreambuf_iterator<char>{source},
                                    std::istreambuf_iterator<char>{});
    kernix::GuestELF guest{};
    const char* reason=nullptr;
    auto profile=kernix::GuestLayout::ManagedHeapSyscalls;
    if(!kernix::loadFixedGuestELF(elf.data(),elf.size(),guest,reason,profile)){
        std::cerr<<"compiled x86 heap ELF64 rejected: "<<reason<<"\n";return 3;
    }
    constexpr char msg[]="KERNIX_ELF_RW_MEMORY_PASS\n";
    if(guest.entry!=guest.executable || guest.executableSize!=149 ||
       guest.messageSize!=32 || guest.writableSize!=32 ||
       ::memcmp(reinterpret_cast<void*>(guest.message),msg,26) ||
       ::memcmp(reinterpret_cast<void*>(guest.writableData),std::string(32,'\0').data(),32)){
        guest.release();return 4;
    }
    guest.release();
    // An old RW ELF profile must not mistakenly accept this new guest.
    if(kernix::loadFixedGuestELF(elf.data(),elf.size(),guest,reason,
                                 kernix::GuestLayout::WritableMemoryCopy)){
        guest.release();return 5;
    }
    for(size_t offset: {0UL,4UL,5UL,16UL,18UL,24UL,56UL}){
        auto mutated=elf;mutated[offset]^=0x55;
        if(kernix::loadFixedGuestELF(mutated.data(),mutated.size(),guest,reason,profile)){
            guest.release();return 6;
        }
    }
    // Fourth PT_LOAD must never acquire executable permission.
    auto corrupted=elf;
    corrupted[64+3*56+4]=7; // R|W|X
    if(kernix::loadFixedGuestELF(corrupted.data(),corrupted.size(),guest,reason,profile)){
        guest.release();return 7;
    }
    std::cout<<"KERNIX_HOST_ELF64_HEAP_SYSCALLS_WX_LOAD_AND_NEGATIVE_GATES_PASS\n";
}
