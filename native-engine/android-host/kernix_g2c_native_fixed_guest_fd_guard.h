#pragma once
// G2-C: pinned read-only ELF fixture descriptors for a future Android child.
// No guest code execution, memory mappings, file writes or Wine integration.
// The file-descriptor set is NOT yet wired into FEX's ELF readers. In-place
// mutation after hashing is still possible until a sealed-snapshot handoff.
// SPDX-License-Identifier: MIT
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace kernix::g2c {

class Sha256 {
    std::array<uint32_t, 8> state{{
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    }};
    std::array<uint8_t, 64> block{};
    size_t used = 0;
    uint64_t bytes = 0;

    static uint32_t Rotate(uint32_t v, unsigned n) {
        return (v >> n) | (v << (32U - n));
    }
    void Compress() {
        static constexpr uint32_t k[64] = {
            0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
            0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
            0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
            0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
            0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
            0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
            0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
            0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
            0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
            0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
            0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
            0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
            0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
            0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
            0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
            0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
        };
        uint32_t w[64]{};
        for (unsigned i = 0; i < 16; ++i) {
            const unsigned p = i * 4;
            w[i] = (uint32_t(block[p]) << 24) |
                   (uint32_t(block[p+1]) << 16) |
                   (uint32_t(block[p+2]) << 8) | uint32_t(block[p+3]);
        }
        for (unsigned i = 16; i < 64; ++i) {
            uint32_t s0 = Rotate(w[i-15],7) ^ Rotate(w[i-15],18) ^
                          (w[i-15] >> 3);
            uint32_t s1 = Rotate(w[i-2],17) ^ Rotate(w[i-2],19) ^
                          (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        auto [a,b,c,d,e,f,g,h] = state;
        for (unsigned i = 0; i < 64; ++i) {
            uint32_t s1 = Rotate(e,6) ^ Rotate(e,11) ^ Rotate(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + s1 + ch + k[i] + w[i];
            uint32_t s0 = Rotate(a,2) ^ Rotate(a,13) ^ Rotate(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        const uint32_t updated[8] = {a,b,c,d,e,f,g,h};
        for (unsigned i = 0; i < 8; ++i) state[i] += updated[i];
    }
public:
    void Update(const uint8_t* data, size_t count) {
        if (!count) return;
        bytes += count;
        while (count) {
            size_t take = 64 - used;
            if (take > count) take = count;
            std::memcpy(block.data() + used, data, take);
            used += take;
            data += take;
            count -= take;
            if (used == 64) { Compress(); used = 0; }
        }
    }
    std::string FinishHex() {
        const uint64_t bitCount = bytes * 8;
        uint8_t one = 0x80;
        Update(&one,1);
        const uint8_t zero = 0;
        while (used != 56) Update(&zero,1);
        uint8_t bits[8];
        for (unsigned i = 0; i < 8; ++i)
            bits[i] = uint8_t(bitCount >> (56 - 8*i));
        Update(bits,8);
        static constexpr char hex[]="0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (uint32_t word : state) {
            for (unsigned shift = 28; shift < 32; shift -= 4) {
                out.push_back(hex[(word >> shift) & 15U]);
                if (shift == 0) break;
            }
        }
        return out;
    }
};

class OwnedFd {
    int value_ = -1;
public:
    OwnedFd() = default;
    explicit OwnedFd(int v) : value_(v) {}
    ~OwnedFd() { reset(); }
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    OwnedFd(OwnedFd&& other) noexcept : value_(other.value_) { other.value_=-1; }
    OwnedFd& operator=(OwnedFd&& other) noexcept {
        if (this != &other) { reset(); value_=other.value_; other.value_=-1; }
        return *this;
    }
    int get() const { return value_; }
    void reset(int v=-1) { if (value_>=0) close(value_); value_=v; }
};

struct FixedGuestFileSet {
    std::array<OwnedFd,4> files;
    bool sha256Verified = false;
    bool descriptorsPinned = false;
    bool executableGuestPagesMapped = false;
    bool guestCodeExecuted = false;
    bool wineTested = false;
};

inline bool VerifyFile(int fd, uint64_t expectedSize, const char* expectedSha) {
    struct stat before{}, after{};
    if (fd<0 || fstat(fd,&before)!=0 || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || uint64_t(before.st_size)!=expectedSize ||
        before.st_uid!=getuid() ||
        (before.st_mode & (S_IWUSR|S_IWGRP|S_IWOTH))) return false;
    Sha256 hash;
    std::array<uint8_t,8192> buffer{};
    uint64_t offset = 0;
    while (offset < expectedSize) {
        size_t wanted = buffer.size();
        if (expectedSize - offset < wanted)
            wanted = static_cast<size_t>(expectedSize - offset);
        const ssize_t count = pread(fd,buffer.data(),wanted,
                                    static_cast<off_t>(offset));
        if (count <= 0) return false;
        hash.Update(buffer.data(),static_cast<size_t>(count));
        offset += static_cast<uint64_t>(count);
    }
    if (fstat(fd,&after)!=0 || before.st_dev!=after.st_dev ||
        before.st_ino!=after.st_ino || before.st_size!=after.st_size ||
        before.st_mtime!=after.st_mtime || before.st_ctime!=after.st_ctime)
        return false;
    return hash.FinishHex()==expectedSha;
}

inline int OpenDirectory(int root, const char* child) {
    return openat(root,child,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
}

// Caller supplies an app-owned exact getFilesDir path, NOT the rootfs path.
// Every subsequent component is a fixed literal, opened relative to a
// pinned directory descriptor. No relative traversal, links, or host /lib.
inline bool PinAndVerifyFixedGuest(const char* appFilesDir,
                                   FixedGuestFileSet& output,
                                   std::string& reason) {
    output.sha256Verified = false;
    output.descriptorsPinned = false;
    for (auto& fd : output.files) fd.reset();
    if (!appFilesDir || appFilesDir[0] != '/' ||
        std::strlen(appFilesDir)>4096) {
        reason="INVALID_PRIVATE_APP_ROOT"; return false;
    }
    OwnedFd app(open(appFilesDir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    struct stat st{};
    if (app.get()<0 || fstat(app.get(),&st)!=0 || st.st_uid!=getuid()) {
        reason="APP_ROOT_MISSING_OR_UNOWNED"; return false;
    }
    OwnedFd kernix(OpenDirectory(app.get(),"kernix"));
    OwnedFd runtime(OpenDirectory(kernix.get(),"runtime-v1"));
    OwnedFd guest(OpenDirectory(runtime.get(),"guest-rootfs"));
    OwnedFd root(OpenDirectory(guest.get(),"g2c-fixed-v1"));
    if (root.get()<0) { reason="FIXED_GUEST_DIRECTORY_UNAVAILABLE"; return false; }
    OwnedFd bin(OpenDirectory(root.get(),"bin"));
    OwnedFd lib(OpenDirectory(root.get(),"lib"));
    OwnedFd lib64(OpenDirectory(root.get(),"lib64"));
    OwnedFd libx(OpenDirectory(lib.get(),"x86_64-linux-gnu"));
    if (bin.get()<0 || libx.get()<0 || lib64.get()<0) {
        reason="GUEST_LIBRARY_DIRECTORY_UNAVAILABLE"; return false;
    }
    struct Item { int dir; const char* name; uint64_t bytes; const char* sha; };
    const std::array<Item,4> specs{{
        {bin.get(),"kernix-dynamic-app",13344,
         "e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a"},
        {libx.get(),"libc.so.6",2118168,
         "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"},
        {libx.get(),"ld-linux-x86-64.so.2",235408,
         "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"},
        {lib64.get(),"ld-linux-x86-64.so.2",235408,
         "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"}
    }};
    for (size_t i = 0; i < specs.size(); ++i) {
        const Item& item=specs[i];
        output.files[i].reset(openat(item.dir,item.name,
                        O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        if (!VerifyFile(output.files[i].get(),item.bytes,item.sha)) {
            for (auto& file : output.files) file.reset();
            reason="GUEST_FD_SHA256_SIZE_OR_SYMLINK_REJECTED";
            return false;
        }
    }
    output.descriptorsPinned = true;
    output.sha256Verified = true;
    reason = "none";
    return true;
}
} // namespace kernix::g2c
