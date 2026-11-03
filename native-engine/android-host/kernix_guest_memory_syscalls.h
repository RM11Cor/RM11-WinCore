// Original KERNIX bounded guest mapping + Linux x86-64 syscall plan.
// SPDX-License-Identifier: MIT
// Only for the immutable in-APK guest fixture. Not a general Linux syscall ABI.
#pragma once
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace kernix {
constexpr std::size_t kHeapSize = 16384;
constexpr std::size_t kGuestMessageLength = 26;
struct SyscallStep {
    std::uint64_t number;
    std::uintptr_t ripOffset;
    std::uintptr_t nextOffset;
};
constexpr std::array<SyscallStep,4> kManagedSyscalls{{
    {9, 39, 41},   // Linux mmap
    {1, 79, 81},   // Linux write
    {39, 88, 90},  // Linux getpid
    {11, 106, 108} // Linux munmap
}};
inline bool validateTrap(std::size_t index, std::uint64_t syscall,
                         std::uintptr_t entry, std::uint64_t rip,
                         std::uint64_t next) noexcept {
    if(index >= kManagedSyscalls.size()) return false;
    const auto& s = kManagedSyscalls[index];
    return syscall == s.number && rip == entry + s.ripOffset &&
           next == entry + s.nextOffset && next == rip + 2;
}
class ManagedGuestHeap final {
public:
    ManagedGuestHeap() = default;
    ManagedGuestHeap(const ManagedGuestHeap&) = delete;
    ManagedGuestHeap& operator=(const ManagedGuestHeap&) = delete;
    ~ManagedGuestHeap() { release(); }
    enum class AllocationResult { Success, AlreadyAllocated, BadArguments, HostMmapFailed };
    // Linux mmap's fifth argument has an int fd ABI. Permit the two
    // canonical sign/zero-extended encodings of fd=-1, never other values.
    static constexpr bool isAnonymousFd(std::uint64_t fd) noexcept {
        return fd == UINT64_MAX || fd == UINT32_MAX;
    }
    AllocationResult allocateChecked(std::uint64_t addr,std::uint64_t len,
                  std::uint64_t prot,std::uint64_t flags,std::uint64_t fd,
                  std::uint64_t off, int* hostErrno=nullptr) noexcept {
        if(hostErrno) *hostErrno=0;
        if(base_ != nullptr) return AllocationResult::AlreadyAllocated;
        if(addr != 0 || len != kHeapSize ||
           prot != (PROT_READ | PROT_WRITE) ||
           flags != (MAP_PRIVATE | MAP_ANONYMOUS) ||
           !isAnonymousFd(fd) || off != 0)
            return AllocationResult::BadArguments;
        errno=0;
        void* address=::mmap(nullptr,kHeapSize,PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
        if(address == MAP_FAILED) {
            if(hostErrno) *hostErrno=errno;
            return AllocationResult::HostMmapFailed;
        }
        base_=address;
        return AllocationResult::Success;
    }
    bool allocate(std::uint64_t addr,std::uint64_t len,std::uint64_t prot,
                  std::uint64_t flags,std::uint64_t fd,std::uint64_t off) noexcept {
        return allocateChecked(addr,len,prot,flags,fd,off) == AllocationResult::Success;
    }
    std::uintptr_t address() const noexcept {
        return reinterpret_cast<std::uintptr_t>(base_);
    }
    bool containsExactMessage(std::uint64_t ptr, std::uint64_t length) const noexcept {
        return base_ && ptr == address() && length == kGuestMessageLength;
    }
    bool matches(const void* message, std::size_t length) const noexcept {
        return base_ && message && length == kGuestMessageLength &&
               ::memcmp(base_,message,length) == 0;
    }
    bool freeByGuest(std::uint64_t ptr,std::uint64_t length) noexcept {
        if(base_ == nullptr || ptr != address() || length != kHeapSize) return false;
        void* pointer=base_;
        base_=nullptr;
        return ::munmap(pointer,kHeapSize)==0;
    }
    bool isUnmapped() const noexcept {return base_==nullptr;}
private:
    void release() noexcept {
        if(base_){ ::munmap(base_,kHeapSize); base_=nullptr; }
    }
    void* base_=nullptr;
};
} // namespace kernix
