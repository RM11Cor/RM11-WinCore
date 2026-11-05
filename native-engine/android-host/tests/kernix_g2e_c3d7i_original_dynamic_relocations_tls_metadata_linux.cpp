// SPDX-License-Identifier: MIT
// C3-D7I Linux AArch64 + x86_64: examine only original unchanged
// SHA-locked main/ld-linux/glibc DT_RELA/DT_RELR/JMPREL/PT_TLS bytes.
// Mutations are NEGATIVE parser fixtures, not real original ELF code.
// NO relocation writes, TLS FS/GS init, guest syscall, FEX or Android.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>
namespace i=kernix::g2e::c3d7i;
namespace g=kernix::g2e::c3d7g;
namespace h=kernix::g2e::c3d7h;
namespace b=kernix::g2e::c3d7b;

static bool RunSyntheticMutationTests(
   const kernix::g2e::GuestPreflight& originals,
   const b::NativeChosenPIEGuestLayout& guest,
   const g::PermissionPlan& perms) {
  bool sawTLS=false;
  for(size_t k=0;k<3;++k) {
    const auto& source=originals.snapshots[k];
    std::vector<unsigned char> altered(
       source.bytes(),source.bytes()+source.size());
    Elf64_Ehdr eh{};
    std::memcpy(&eh,altered.data(),sizeof(eh));
    size_t dynamicOffset=SIZE_MAX,tlsOffset=SIZE_MAX;
    for(uint16_t n=0;n<eh.e_phnum;++n) {
      Elf64_Phdr ph{};
      const size_t at=size_t(eh.e_phoff)+n*sizeof(ph);
      std::memcpy(&ph,altered.data()+at,sizeof(ph));
      if(ph.p_type==PT_DYNAMIC && dynamicOffset==SIZE_MAX)
        dynamicOffset=static_cast<size_t>(ph.p_offset);
      if(ph.p_type==PT_TLS && tlsOffset==SIZE_MAX)
        tlsOffset=at;
    }
    if(dynamicOffset==SIZE_MAX)return false;
    i::Reject why=i::Reject::None;
    const auto inspect=[&](i::Reject& reason) {
      i::ModuleDynamic d;
      return i::InspectModule(
        altered.data(),altered.size(),
        *guest.Module(k),perms.modules[k],d,reason);
    };
    // Source-bound DT_STRSZ required. Huge size must be rejected
    // without attempting host memory mapping or relocation.
    size_t strSizeAt=SIZE_MAX,strTabAt=SIZE_MAX,relrAt=SIZE_MAX;
    for(size_t d=dynamicOffset;
        d+sizeof(Elf64_Dyn)<=altered.size();
        d+=sizeof(Elf64_Dyn)) {
      Elf64_Dyn entry{};
      std::memcpy(&entry,altered.data()+d,sizeof(entry));
      if(entry.d_tag==DT_NULL)break;
      if(entry.d_tag==DT_STRSZ)strSizeAt=d;
      if(entry.d_tag==DT_STRTAB)strTabAt=d;
      if(entry.d_tag==DT_RELR)relrAt=d;
      if(d-dynamicOffset>65536)return false;
    }
    if(strSizeAt==SIZE_MAX || strTabAt==SIZE_MAX)return false;
    Elf64_Dyn orig{};
    std::memcpy(&orig,altered.data()+strSizeAt,sizeof(orig));
    Elf64_Dyn bad=orig;
    bad.d_un.d_val=UINT64_MAX;
    std::memcpy(altered.data()+strSizeAt,&bad,sizeof(bad));
    why=i::Reject::None;
    if(inspect(why) ||
       why!=i::Reject::MissingDynamicStringTable) {
      std::fprintf(stderr,
        "C3D7I_INVALID_STRTAB_REJECTION_FAIL module=%zu reject=%u\n",
        k,unsigned(why));
      return false;
    }
    std::memcpy(altered.data()+strSizeAt,&orig,sizeof(orig));

    // A fabricated DT_TEXTREL is never a reason to grant WX.
    std::memcpy(&orig,altered.data()+strTabAt,sizeof(orig));
    bad=orig;bad.d_tag=DT_TEXTREL;
    std::memcpy(altered.data()+strTabAt,&bad,sizeof(bad));
    why=i::Reject::None;
    if(inspect(why) ||
       why!=i::Reject::TextRelocationsForbidden) {
      std::fprintf(stderr,
        "C3D7I_SYNTHETIC_TEXTREL_NOT_DENIED module=%zu reject=%u\n",
        k,unsigned(why));
      return false;
    }
    std::memcpy(altered.data()+strTabAt,&orig,sizeof(orig));
    // A corrupt RELR guest table pointer must be rejected before
    // any attempted writes, even when all physical file bytes exist.
    if(relrAt!=SIZE_MAX) {
      std::memcpy(&orig,altered.data()+relrAt,sizeof(orig));
      bad=orig;bad.d_un.d_val=UINT64_MAX;
      std::memcpy(altered.data()+relrAt,&bad,sizeof(bad));
      why=i::Reject::None;
      if(inspect(why) || why!=i::Reject::BadDynamicTable) {
        std::fprintf(stderr,
          "C3D7I_SYNTHETIC_RELR_SOURCE_POINTER_NOT_REJECTED module=%zu reason=%u\n",
          k,unsigned(why));
        return false;
      }
      std::memcpy(altered.data()+relrAt,&orig,sizeof(orig));
    }

    // A malformed PT_TLS does not authorize touching FS/GS.
    if(tlsOffset!=SIZE_MAX) {
      sawTLS=true;
      Elf64_Phdr tls{};
      std::memcpy(&tls,altered.data()+tlsOffset,sizeof(tls));
      bad={};
      Elf64_Phdr corrupt=tls;
      corrupt.p_memsz=0;
      std::memcpy(altered.data()+tlsOffset,&corrupt,sizeof(corrupt));
      why=i::Reject::None;
      if(inspect(why) || why!=i::Reject::MalformedTLS) {
        std::fprintf(stderr,
          "C3D7I_SYNTHETIC_TLS_REJECTION_FAIL module=%zu reject=%u\n",
          k,unsigned(why));
        return false;
      }
      std::memcpy(altered.data()+tlsOffset,&tls,sizeof(tls));
    }
    if(std::memcmp(source.bytes(),altered.data(),altered.size())!=0)
      return false;
  }
  return sawTLS;
}
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(sysconf(_SC_PAGESIZE)!=4096)return 3;
  int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(root<0)return 4;
  kernix::g2e::GuestPreflight original;
  std::string why;
  if(!kernix::g2e::Validate(root,original,why)) {
    std::fprintf(stderr,"C3D7I_AUTHENTIC_SOURCE_REJECTED %s\n",why.c_str());
    close(root);return 5;
  }
  b::NativeChosenPIEGuestLayout owned;
  b::Witness witness;
  std::array<uint8_t,16> seed{};
  for(size_t t=0;t<16;++t)seed[t]=uint8_t(t+1);
  if(!owned.Stage(root,seed,witness) ||
     !witness.pinnedOriginalELFSHA256Verified ||
     witness.originalLdsoExecuted ||
     witness.originalELFCodeExecuted ||
     owned.WindowsHeld()!=4) {
    close(root);return 6;
  }
  close(root);
  g::PermissionPlan page;
  g::Reject pageReject;
  if(!g::BuildVerifiedOriginalPermissionPlan(
      original,owned,page,pageReject))return 7;
  h::Plan relro;
  h::Reject relroReject;
  if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
      original,owned,page,relro,relroReject))return 8;
  i::Plan dynamic;
  i::Reject reason;
  if(!i::InspectOriginalThreeModules(
      original,owned,page,relro,dynamic,reason)) {
    std::fprintf(stderr,"C3D7I_ORIGINAL_DYNAMIC_METADATA_REJECTED reason=%u\n",
      unsigned(reason));
    for(size_t k=0;k<3;++k) {
      i::ModuleDynamic temp{};
      i::Reject local{};
      const auto& src=original.snapshots[k];
      const bool ok=i::InspectModule(src.bytes(),src.size(),
         *owned.Module(k),page.modules[k],temp,local);
      std::fprintf(stderr,
        "C3D7I_MODULE_%zu ok=%d reason=%u dyn=%zu needed=%zu rela=%zu plt=%zu relr=%zu tls=%zu\n",
        k,int(ok),unsigned(local),temp.dynamicEntries,
        temp.neededLibraries,temp.relaEntries,temp.pltRelaEntries,
        temp.relrWords,temp.tlsHeaders);
    }
    return 9;
  }
  if(!dynamic.originalThreeSHA256SourcesVerified ||
     !dynamic.allOriginalDynamicTablesBounded ||
     !dynamic.allOriginalTLSRangesBounded ||
     dynamic.x86GuestFSGSInitialized ||
     dynamic.originalELFRelocationsApplied ||
     dynamic.originalLinuxLdsoExecuted ||
     dynamic.relroSealed ||
     dynamic.androidDeviceTested ||
     dynamic.originalDynamicEntries==0 ||
     dynamic.totalNeededLibraries==0 ||
     dynamic.totalValidatedNeededStrings!=dynamic.totalNeededLibraries ||
     dynamic.totalRelrTargets==0 ||
     dynamic.relocationTargetsOutsideInitialRW!=0 ||
     dynamic.totalRelaEntries==0 ||
     dynamic.totalTLSHeaders==0)
    return 10;
  for(size_t k=0;k<3;++k) {
    const auto& module=dynamic.modules[k];
    std::fprintf(stdout,
      "C3D7I_AUTHENTIC_MODULE_%zu dynamic=%zu needed=%zu neededStrings=%zu rela=%zu plt=%zu relrWords=%zu relrTargets=%zu relative=%zu irelative=%zu symbolic=%zu notInitiallyRW=%zu outsideImage=%zu tls=%zu tlsInit=%llu tlsMemory=%llu tlsAlign=%llu\n",
      k,module.dynamicEntries,module.neededLibraries,
      module.validatedNeededStrings,
      module.relaEntries,module.pltRelaEntries,module.relrWords,
      module.relrTargets,module.relativeRelaEntries,module.irelativeRelaEntries,
      module.symbolicRelaEntries,module.relocationTargetsNotInitialRW,
      module.relocationTargetsOutsideImage,module.tlsHeaders,
      static_cast<unsigned long long>(module.tlsInitFileSize),
      static_cast<unsigned long long>(module.tlsTotalMemorySize),
      static_cast<unsigned long long>(module.tlsAlignment));
    if(!module.hasDynamic || !module.tagsStrictlyBounded ||
       !module.relocationTablesWithinOriginalFileBytes ||
       module.originalImageVA!=page.modules[k].nativeOwnedStart ||
       module.fsgsInitialized || module.guestRelocationsApplied)
      return 11;
  }
  if(!RunSyntheticMutationTests(original,owned,page))
    return 12;
  if(!owned.Release() || owned.WindowsHeld()!=0)
    return 13;
  std::puts(
    "KERNIX_G2EC3D7I_AUTHENTIC_LINUX_X86_ELF_DYNAMIC_RELA_RELR_TLS_METADATA_BOUNDED_PASS"
    " source_three_sha256=1"
    " real_dynamic_tags=1"
    " original_rela_and_plt_tables_bounds_checked=1"
    " source_reloc_types_counted=1"
    " original_pt_tls_header_bounds_checked=1"
    " original_relr_bitmap_targets_decoded_and_within_rw=1"
    " source_needed_library_names_bounded_and_nul_terminated=1"
    " total_tls_at_least_one=1"
    " reject_fake_dt_strsz_overflow=1"
    " reject_fake_relr_source_pointer=1"
    " reject_fake_textrel=1"
    " reject_fake_tls_zero_memsz=1"
    " original_entry_and_relro_plan_preserved=1"
    " original_relocations_written=0"
    " x86_fs_gs_initialized=0"
    " relro_sealed=0"
    " original_ldso_executed=0"
    " fex=0 android_device=0 wine=0");
  return 0;
}
