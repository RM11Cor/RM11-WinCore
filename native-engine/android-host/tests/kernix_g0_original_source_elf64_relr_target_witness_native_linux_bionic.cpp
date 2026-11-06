// SPDX-License-Identifier: MIT
// Original SHA-verified source GNU/Linux x86 ELF64 DT_RELR witness only.
// No original ld-linux execution, no guest opcode, no relocation applied.
// CI copies exactly SHA256-verified main/ld-linux/libc from original source.
#include "kernix_g0_original_source_relr_target_witness.h"
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
namespace relr=kernix::g0::relr;
static std::vector<uint8_t> ReadExact(const std::string& path,size_t expected){
  const int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  assert(fd>=0);
  struct stat st{};
  assert(::fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
         st.st_size>=0 && static_cast<uint64_t>(st.st_size)==expected);
  std::vector<uint8_t> b(expected);
  size_t off=0;
  while(off<b.size()){
    const auto got=::read(fd,b.data()+off,b.size()-off);
    assert(got>0);off+=static_cast<size_t>(got);
  }
  assert(::close(fd)==0);return b;
}
int main(int argc,char** argv){
  if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
  const std::string base(argv[1]);
  const std::array<std::string,3> paths{{
     base+"/bin/kernix-g2e-dynamic-guest",
     base+"/lib64/ld-linux-x86-64.so.2",
     base+"/lib/x86_64-linux-gnu/libc.so.6"
  }};
  constexpr std::array<size_t,3> sizes{{15976,235408,2118168}};
  constexpr uint64_t kCandidateBias=0x0000000700000000ULL;
  relr::Witness selected{};
  std::vector<uint8_t> selectedSource;
  size_t sourceIndex=3;
  size_t relrWordsFound=0,totalTargets=0,sourceTargets=0,candidates=0;
  for(size_t i=0;i<paths.size();++i){
    auto src=ReadExact(paths[i],sizes[i]);
    relr::Witness unauth{};
    relr::Reject rejected{};
    assert(!relr::SourceOriginalRELRWitness(src.data(),src.size(),
              false,kCandidateBias,unauth,rejected) &&
           rejected==relr::Reject::OriginalSourceNotAttested &&
           !unauth.authenticSourceELF64DynamicRELR);
    relr::Witness witness{};
    const bool good=relr::SourceOriginalRELRWitness(
        src.data(),src.size(),true,kCandidateBias,witness,rejected);
    if(!good){
      assert(rejected==relr::Reject::MissingRELR ||
             rejected==relr::Reject::NoSafeSourceTarget);
      continue;
    }
    assert(rejected==relr::Reject::None &&
           witness.authenticSourceELF64DynamicRELR &&
           witness.sourceDescriptorDecoded &&
           witness.verifiedGuestRWTargetNotExecutable &&
           !witness.guestRelocationActuallyExecuted &&
           !witness.originalLdsoRelocationActuallyExecuted &&
           witness.sourceTableVA>0 && witness.sourceTableSize>0 &&
           witness.relrWords>0 && witness.totalDecodedTargets>0 &&
           witness.sourceBackedWritableTargets>0 &&
           witness.sourceImageAddendCandidates>0 &&
           witness.sourceDescriptorIndex<witness.relrWords &&
           witness.guestLoadBias==kCandidateBias &&
           witness.guestTarget==kCandidateBias+witness.sourceTargetVA &&
           witness.expectedRelocatedPointer==
             kCandidateBias+witness.sourceInitialAddend &&
           witness.sourceTargetFileOffset<=src.size()-8);
    uint64_t initial=0;
    std::memcpy(&initial,src.data()+witness.sourceTargetFileOffset,8);
    assert(initial==witness.sourceInitialAddend);
    relrWordsFound+=witness.relrWords;
    totalTargets+=witness.totalDecodedTargets;
    sourceTargets+=witness.sourceBackedWritableTargets;
    candidates+=witness.sourceImageAddendCandidates;
    if(sourceIndex==3){
      selected=witness;
      selectedSource=std::move(src);
      sourceIndex=i;
    }
  }
  assert(sourceIndex<3 && !selectedSource.empty() && relrWordsFound>0 &&
         totalTargets>0 && sourceTargets>0 && candidates>0);
  // Independently verify the selected descriptor's physical source
  // provenance: it's exactly an ELF PT_LOAD PT_DYNAMIC DT_RELR
  // descriptor, not an arbitrary guessed pointer in guest memory.
  Elf64_Ehdr eh{};
  std::memcpy(&eh,selectedSource.data(),sizeof(eh));
  uint64_t tableVA=0,tableBytes=0,tableEnt=0;
  bool seenRelr=false,seenSize=false,seenEnt=false,terminated=false;
  for(size_t i=0;i<eh.e_phnum;++i){
    Elf64_Phdr ph{};
    std::memcpy(&ph,selectedSource.data()+eh.e_phoff+i*sizeof(ph),
                sizeof(ph));
    if(ph.p_type!=PT_DYNAMIC)continue;
    for(size_t o=0;o<ph.p_filesz;o+=sizeof(Elf64_Dyn)){
      Elf64_Dyn entry{};
      std::memcpy(&entry,selectedSource.data()+ph.p_offset+o,
                  sizeof(entry));
      if(entry.d_tag==DT_NULL){terminated=true;break;}
      if(entry.d_tag==DT_RELR){tableVA=entry.d_un.d_ptr;seenRelr=true;}
      if(entry.d_tag==DT_RELRSZ){tableBytes=entry.d_un.d_val;seenSize=true;}
      if(entry.d_tag==DT_RELRENT){tableEnt=entry.d_un.d_val;seenEnt=true;}
    }
  }
  assert(seenRelr && seenSize && seenEnt && terminated &&
         tableVA==selected.sourceTableVA &&
         tableBytes==selected.sourceTableSize && tableEnt==8);
  relr::Phdrs phs{};
  phs.count=eh.e_phnum;
  for(size_t i=0;i<eh.e_phnum;++i){
    std::memcpy(&phs.entries[i],selectedSource.data()+eh.e_phoff+
            i*sizeof(Elf64_Phdr),sizeof(Elf64_Phdr));
  }
  size_t tableOff=0,writableOff=0;
  assert(relr::SourcePTLoadFileVA(phs,selectedSource.size(),
         tableVA,tableBytes,tableOff) &&
         relr::SourceTargetInWritableNonExecutablePTLoad(phs,
           selectedSource.size(),selected.sourceTargetVA,writableOff) &&
         writableOff==selected.sourceTargetFileOffset &&
         relr::SourcePointerInsidePTLoad(phs,selected.sourceInitialAddend));
  uint64_t selectedOriginalWord=0;
  std::memcpy(&selectedOriginalWord,
    selectedSource.data()+tableOff+selected.sourceDescriptorIndex*8,8);
  assert(selectedOriginalWord==selected.sourceDescriptorWord);
  // Regression: never trust a corrupted table header, a caller without
  // source attestation, a bogus ELF magic or truncated source bytes.
  auto corrupted=selectedSource;
  corrupted[0]^=0x7f;
  relr::Witness bad{};
  relr::Reject why{};
  assert(!relr::SourceOriginalRELRWitness(corrupted.data(),
           corrupted.size(),true,kCandidateBias,bad,why) &&
         why==relr::Reject::MalformedELF);
  corrupted=selectedSource;
  Elf64_Ehdr invalid{};
  std::memcpy(&invalid,corrupted.data(),sizeof(invalid));
  invalid.e_phoff=UINT64_MAX-8;
  std::memcpy(corrupted.data(),&invalid,sizeof(invalid));
  assert(!relr::SourceOriginalRELRWitness(corrupted.data(),
           corrupted.size(),true,kCandidateBias,bad,why) &&
         why==relr::Reject::MalformedELF);
  assert(!relr::SourceOriginalRELRWitness(selectedSource.data(),
         24,true,kCandidateBias,bad,why) &&
         why==relr::Reject::MalformedELF);
  // Candidate bias is chosen by a future native guest-ownership gate.
  // The source addend only maps to an address when no uint64 overflow
  // would occur. This contract explicitly does NOT write a relocation.
  assert(selected.guestTarget>selected.sourceTargetVA &&
         selected.expectedRelocatedPointer>selected.sourceInitialAddend);
  std::printf("KERNIX_G0_REAL_ORIGINAL_SHA256_ELF64_DYNAMIC_RELR_COMPACT_SOURCE_RW_TARGET_AND_ADDEND_LINUX_PASS_NO_GUEST_WRITE module=%zu words=%zu targets=%zu source_targets=%zu candidates=%zu target_va=%llu\n",
       sourceIndex,relrWordsFound,totalTargets,sourceTargets,candidates,
       static_cast<unsigned long long>(selected.sourceTargetVA));
  return 0;
}
