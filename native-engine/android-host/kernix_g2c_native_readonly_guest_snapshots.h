#pragma once
// KERNIX G2-C: copy the four fixed, SHA-256-verified x86 guest file FDs into
// private read-only ANONYMOUS memory snapshots. No guest FEX execution.
// This does not yet plumb FEX ELF reads through the snapshot. It only proves
// immutable bytes independent of subsequent app-private source file changes.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_fixed_guest_fd_guard.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <string>
#include <sys/mman.h>

namespace kernix::g2c {

class ReadonlyGuestSnapshot {
    void* mapping_ = nullptr;
    size_t size_ = 0;
public:
    ReadonlyGuestSnapshot() = default;
    ~ReadonlyGuestSnapshot() { reset(); }
    ReadonlyGuestSnapshot(const ReadonlyGuestSnapshot&) = delete;
    ReadonlyGuestSnapshot& operator=(const ReadonlyGuestSnapshot&) = delete;
    ReadonlyGuestSnapshot(ReadonlyGuestSnapshot&& other) noexcept
      : mapping_(other.mapping_),size_(other.size_) {
        other.mapping_=nullptr; other.size_=0;
    }
    ReadonlyGuestSnapshot& operator=(ReadonlyGuestSnapshot&& other) noexcept {
        if (this!=&other) {
            reset(); mapping_=other.mapping_; size_=other.size_;
            other.mapping_=nullptr; other.size_=0;
        }
        return *this;
    }
    void reset() noexcept {
        if (mapping_) munmap(mapping_,size_);
        mapping_=nullptr;
        size_=0;
    }
    const uint8_t* bytes() const noexcept {
        return static_cast<const uint8_t*>(mapping_);
    }
    size_t size() const noexcept { return size_; }
    bool readOnlySnapshot() const noexcept { return mapping_ && size_; }

    bool Capture(int verifiedFd,size_t expectedBytes,const char* sha,
                 std::string& reason) {
        reset();
        if (verifiedFd<0 || expectedBytes<64 || expectedBytes>4*1024*1024 ||
            !sha || std::strlen(sha)!=64) {
            reason="G2C_SNAPSHOT_INVALID_INPUT"; return false;
        }
        // This is MAP_PRIVATE anonymous: the mmap holds no pages from the
        // disk ELF and cannot change when that file is edited afterwards.
        void* address=mmap(nullptr,expectedBytes,PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (address==MAP_FAILED) {
            reason="G2C_SNAPSHOT_ANON_MMAP_FAILED"; return false;
        }
        // Capture an exact immutable byte image using pread from the
        // already-verified FD. Rehash the captured copy, not the path/FD.
        size_t at=0;
        while (at<expectedBytes) {
            size_t count=expectedBytes-at;
            if (count>8192)count=8192;
            const ssize_t n=pread(verifiedFd,
                static_cast<uint8_t*>(address)+at,count,
                static_cast<off_t>(at));
            if(n<=0) {
                munmap(address,expectedBytes);
                reason="G2C_SNAPSHOT_SHORT_READ";return false;
            }
            at+=static_cast<size_t>(n);
        }
        Sha256 verify;
        verify.Update(static_cast<const uint8_t*>(address),expectedBytes);
        if (verify.FinishHex()!=sha) {
            munmap(address,expectedBytes);
            reason="G2C_SNAPSHOT_DATA_SHA256_REJECTED";return false;
        }
        if(mprotect(address,expectedBytes,PROT_READ)!=0) {
            munmap(address,expectedBytes);
            reason="G2C_SNAPSHOT_READONLY_MPROTECT_FAILED";return false;
        }
        mapping_=address;
        size_=expectedBytes;
        reason="none";
        return true;
    }
};

struct FixedGuestSnapshots {
    std::array<ReadonlyGuestSnapshot,4> files;
    bool allHashesVerified = false;
    bool sourceFileChangesIgnored = false; // proven by adversarial host tests only
    bool handedToFEX = false;
    bool guestExecuted = false;
    bool interpreterExecuted = false;
    bool wineTested = false;
    void reset() noexcept {
        for(auto& f:files)f.reset();
        allHashesVerified=false;
        sourceFileChangesIgnored=false;
        handedToFEX=false;
        guestExecuted=false;
        interpreterExecuted=false;
        wineTested=false;
    }
};

inline bool CaptureVerifiedFixedGuest(const FixedGuestFileSet& source,
                                      FixedGuestSnapshots& out,
                                      std::string& reason) {
    out.reset();
    if(!source.sha256Verified || !source.descriptorsPinned ||
       source.guestCodeExecuted || source.executableGuestPagesMapped ||
       source.wineTested) {
        reason="G2C_SNAPSHOT_SOURCE_NOT_ATTESTED";return false;
    }
    struct Spec { size_t size; const char* sha; };
    static constexpr std::array<Spec,4> kSpecs{{
        {13344,"e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a"},
        {2118168,"7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"},
        {235408,"cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"},
        {235408,"cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"}
    }};
    constexpr size_t kMaximumTotalBytes=3*1024*1024;
    size_t total=0;
    for(size_t i=0;i<kSpecs.size();++i) {
        if(total>kMaximumTotalBytes-kSpecs[i].size ||
           !out.files[i].Capture(source.files[i].get(),kSpecs[i].size,
                                 kSpecs[i].sha,reason)) {
            out.reset();
            if(reason=="none")reason="G2C_SNAPSHOT_TOTAL_CAP_EXCEEDED";
            return false;
        }
        total+=kSpecs[i].size;
    }
    out.allHashesVerified=true;
    reason="none";
    return true;
}

inline bool PinAndCaptureFixedGuest(const char* appFilesDir,
                                    FixedGuestSnapshots& out,
                                    std::string& reason) {
    FixedGuestFileSet source;
    if(!PinAndVerifyFixedGuest(appFilesDir,source,reason)) {
        out.reset();return false;
    }
    return CaptureVerifiedFixedGuest(source,out,reason);
}
} // namespace kernix::g2c
