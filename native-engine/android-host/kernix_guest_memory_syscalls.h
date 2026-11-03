// Original KERNIX bounded guest mapping + Linux x86-64 syscall plan.
// SPDX-License-Identifier: MIT
// Only for the immutable in-APK guest fixture. Not a general Linux syscall ABI.
#pragma once
#include <array>
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
    {9, 33, 35},   // Linux mmap
    {1, 73, 75},   // Linux write
    {39, 82, 84},  // Linux getpid
    {11, 100, 102} // Linux munmap
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
    bool allocate(std::uint64_t addr,std::uint64_t len,std::uint64_t prot,
                  std::uint64_t flags,std::uint64_t fd,std::uint64_t off) noexcept {
        if (base_ != nullptr || addr != 0 || len != kHeapSize ||
            prot != (PROT_READ | PROT_WRITE) ||
            flags != (MAP_PRIVATE | MAP_ANONYMOUS) ||
            fd != UINT64_MAX || off != 0) return false;
        void* address = ::mmap(nullptr,kHeapSize,PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
        if(address == MAP_FAILED) return false;
        base_ = address;
        return true;
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
