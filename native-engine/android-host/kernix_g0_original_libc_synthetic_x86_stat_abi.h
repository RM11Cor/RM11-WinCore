// SPDX-License-Identifier: MIT
#pragma once
// Diagnostic-only KERNIX Linux x86-64 guest struct stat layout.
// ABI source: Linux arch/x86/include/uapi/asm/stat.h (__x86_64__),
// also matched by glibc x86-64 bits/struct_stat.h.
// This is NOT Android/aarch64 native struct stat; never memcpy host stat.
// All metadata except source SHA-verified exact st_size is explicitly
// synthetic for KERNIX's private virtual libc snapshot filesystem.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace kernix::g0::statabi {
struct LinuxX86_64Stat {
  uint64_t device;                // 0
  uint64_t inode;                 // 8
  uint64_t hardLinks;             // 16
  uint32_t mode;                  // 24
  uint32_t uid;                   // 28
  uint32_t gid;                   // 32
  uint32_t zeroPad0;              // 36
  uint64_t specialDevice;         // 40
  int64_t  size;                  // 48
  int64_t  blockSize;             // 56
  int64_t  allocated512Blocks;    // 64
  int64_t  accessSec;             // 72
  uint64_t accessNanosec;         // 80
  int64_t  modifySec;             // 88
  uint64_t modifyNanosec;         // 96
  int64_t  changeSec;             // 104
  uint64_t changeNanosec;         // 112
  int64_t  reserved[3];           // 120..143
};
static_assert(std::endian::native==std::endian::little,
              "Original x86-64 stat requires LE guest semantics");
static_assert(std::is_standard_layout_v<LinuxX86_64Stat>);
static_assert(sizeof(LinuxX86_64Stat)==144);
static_assert(offsetof(LinuxX86_64Stat,inode)==8);
static_assert(offsetof(LinuxX86_64Stat,hardLinks)==16);
static_assert(offsetof(LinuxX86_64Stat,mode)==24);
static_assert(offsetof(LinuxX86_64Stat,specialDevice)==40);
static_assert(offsetof(LinuxX86_64Stat,size)==48);
static_assert(offsetof(LinuxX86_64Stat,blockSize)==56);
static_assert(offsetof(LinuxX86_64Stat,allocated512Blocks)==64);
static_assert(offsetof(LinuxX86_64Stat,accessSec)==72);
static_assert(offsetof(LinuxX86_64Stat,changeSec)==104);
static_assert(offsetof(LinuxX86_64Stat,reserved)==120);

// Virtual filesystem identity is not masquerading as host inode,
// timestamps, ownership, or native kernel file attributes.
// File content/size independently come from the already SHA256-pinned
// original ELF snapshot; this structure expresses virtual guest metadata.
inline constexpr LinuxX86_64Stat SourcePinnedLibcVirtualStat(
    uint64_t size, uint32_t guestUid, uint32_t guestGid) noexcept {
  LinuxX86_64Stat s{};
  s.device=0x4b45524e4958ULL;         // KERNIX virtual-only filesystem
  s.inode=0x7e262ac92a454f36ULL;      // original libc SHA256 prefix
  s.hardLinks=1;
  s.mode=0100000U | 0444U;             // regular, virtual read-only file
  s.uid=guestUid;
  s.gid=guestGid;
  s.specialDevice=0;
  s.size=static_cast<int64_t>(size);
  s.blockSize=4096;
  s.allocated512Blocks=static_cast<int64_t>((size+511)/512);
  return s;
}
} // namespace kernix::g0::statabi
