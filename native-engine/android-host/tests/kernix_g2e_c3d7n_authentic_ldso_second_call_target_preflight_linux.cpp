// SPDX-License-Identifier: MIT
// C3-D7N original SHA-pinned Linux ld-linux e_entry second x86 CALL
// rel32 actual source-backed RX target, no guest execution/patch.
// Linux AArch64 & x86_64. Mutation negative tests are synthetic.
#include "kernix_g2e_c3d7n_original_ldso_call_source_target_gate.h"
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
namespace n=kernix::g2e::c3d7n;
namespace g=kernix::g2e::c3d7g;
namespace b=kernix::g2e::c3d7b;
int main(int argc,char** argv) {
  if(argc!=2 || !argv[1])return 2;
  if(::sysconf(_SC_PAGESIZE)!=4096)return 3;
  const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return 4;
  kernix::g2e::GuestPreflight original;
  std::string err;
  if(!kernix::g2e::Validate(fd,original,err)) {
    std::fprintf(stderr,"C3D7N_SHA_REJECTED %s\n",err.c_str());
    ::close(fd);return 5;
  }
  b::NativeChosenPIEGuestLayout guest;
  b::Witness stage;
  std::array<uint8_t,16> seed{};
  for(size_t k=0;k<16;++k)seed[k]=uint8_t(k+1);
  if(!guest.Stage(fd,seed,stage) ||
     !stage.pinnedOriginalELFSHA256Verified ||
     stage.originalELFCodeExecuted || stage.originalLdsoExecuted ||
     guest.WindowsHeld()!=4) {
    ::close(fd);return 6;
  }
  ::close(fd);
  g::PermissionPlan policy;
  g::Reject pageErr;
  if(!g::BuildVerifiedOriginalPermissionPlan(
       original,guest,policy,pageErr))return 7;
  n::CallProof call;
  n::Reject reason;
  if(!n::VerifyAuthenticLdsoSecondCallTarget(
       original,guest,policy,call,reason)) {
    std::fprintf(stderr,"C3D7N_ORIGINAL_CALL_SOURCE_REJECT reason=%u\n",
                 unsigned(reason));
    return 8;
  }
  if(!call.originalEntry || !call.originalTarget ||
     !call.pinnedSourceElfSHA256Verified ||
     !call.originalEntryAndTargetFileBackedRX ||
     !call.originalCALLRel32Whitelisted ||
     !call.guestReturnSlotInitiallyWritable ||
     !call.noSourceFileModified || !call.noExecutionOrPatch ||
     call.originalReturnRIP!=call.originalEntry+8 ||
     call.originalGuestStartupRSP!=guest.LaunchPlan()->stack.guestRSP ||
     call.originalEntryBytes[0]!=0x48 ||
     call.originalEntryBytes[1]!=0x89 ||
     call.originalEntryBytes[2]!=0xe7 ||
     call.originalEntryBytes[3]!=0xe8)return 9;
  uint64_t decoded=0;
  int32_t rel=0;
  // The mutated buffers are NOT original attested source ELF.
  std::array<uint8_t,16> mutation=call.originalEntryBytes;
  mutation[3]=0x90;
  if(n::DecodeSourceOriginalRel32CALL(
       mutation.data(),mutation.size(),call.originalEntry,
       decoded,rel,reason) ||
     reason!=n::Reject::OpcodeNotWhitelisted)return 10;
  mutation=call.originalEntryBytes;
  if(n::DecodeSourceOriginalRel32CALL(
       mutation.data(),mutation.size(),0,
       decoded,rel,reason) ||
     reason!=n::Reject::RelativeCallArithmeticInvalid)return 11;
  mutation=call.originalEntryBytes;
  if(!n::DecodeSourceOriginalRel32CALL(
       mutation.data(),mutation.size(),call.originalEntry,
       decoded,rel,reason) ||
     decoded!=call.originalTarget ||
     rel!=call.relativeDisplacement)return 12;
  const auto& src=original.snapshots[1];
  if(std::memcmp(src.bytes()+call.originalSourceEntryFileOffset,
                 call.originalEntryBytes.data(),16)!=0 ||
     std::memcmp(src.bytes()+call.originalSourceTargetFileOffset,
                 call.originalTargetBytes.data(),16)!=0)
    return 13;
  std::printf(
    "C3D7N_REAL_ORIGINAL_LDSO_CALL_REL32_SOURCE_TRACE"
    " displacement=%d"
    " target_elf_offset=%zu"
    " entry_elf_offset=%zu"
    " first_target_opcode=%02x\n",
    call.relativeDisplacement,
    call.originalSourceTargetFileOffset,
    call.originalSourceEntryFileOffset,
    unsigned(call.originalTargetBytes[0]));
  if(!guest.Release() || guest.WindowsHeld()!=0)return 14;
  std::puts(
    "KERNIX_G2EC3D7N_ORIGINAL_LDSO_SECOND_CALL_REL32_SOURCE_RX_PREFLIGHT_LINUX_PASS"
    " sha256_original_three=1"
    " original_two_entry_instructions_source_verified=1"
    " true_second_rel32_call_source_target_computed=1"
    " original_call_target_file_backed_rx=1"
    " guest_return_stack_slot_bounded=1"
    " malicious_wrong_opcode_denied=1"
    " malicious_guest_address_arithmetic_denied=1"
    " original_source_and_guest_image_unchanged=1"
    " all_four_guest_windows_released=1"
    " original_second_call_executed=0"
    " original_ldso_startup=0"
    " fex=0 android=0 wine=0");
  return 0;
}
