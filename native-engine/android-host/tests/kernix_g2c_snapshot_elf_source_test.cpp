// G2-C: PT_LOAD main/interpreter staging uses captured x86 bytes ONLY.
// POSIX Linux host CI; not a FEX JIT / glibc runtime / Android device test.
#include "kernix_g2c_snapshot_elf_source.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using kernix::g2c::FixedGuestSnapshots;
using kernix::g2c::VerifiedSnapshotElfImages;
using kernix::g2c::PinAndCaptureFixedGuest;
using kernix::g2c::StageFixedMainAndInterpreterFromSnapshots;

static void CheckStagedSegments(
    const kernix::g2b::GuestReadonlyImage& staged,
    const kernix::g2c::ReadonlyGuestSnapshot& original) {
    assert(staged.hostView && staged.hostViewReadOnly &&
           !staged.hostViewExecutable && !staged.guestCodeExecuted);
    bool sawText=false;
    for (const auto& segment : staged.segments) {
        const uint64_t relative=segment.guestVaddr-staged.guestPageAlignedBase;
        assert(relative+segment.memoryBytes<=staged.hostViewBytes);
        assert(segment.fileOffset+segment.fileBytes<=original.size());
        const auto* host=static_cast<const uint8_t*>(staged.hostView)+relative;
        assert(std::memcmp(host,original.bytes()+segment.fileOffset,
                           segment.fileBytes)==0);
        for(size_t i=static_cast<size_t>(segment.fileBytes);
            i<segment.memoryBytes;++i)
            assert(host[i]==0);
        if(segment.guestFlags & PF_X)sawText=true;
    }
    assert(sawText);
}

static bool FailFromBytes(const unsigned char* data,size_t len) {
    kernix::g2b::GuestReadonlyImage invalid;
    std::string reason;
    return !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
        std::span<const unsigned char>(data,len),invalid,reason,true) &&
        invalid.hostView==nullptr;
}

int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || argv[1][0]!='/')return 2;
    const std::string app(argv[1]);
    const std::string file=app+
      "/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1/bin/kernix-dynamic-app";
    FixedGuestSnapshots source;
    std::string why;
    assert(PinAndCaptureFixedGuest(app.c_str(),source,why));
    VerifiedSnapshotElfImages image;
    assert(StageFixedMainAndInterpreterFromSnapshots(source,image,why));
    assert(image.mainFromVerifiedSnapshot &&
           image.interpreterFromVerifiedSnapshot &&
           !image.sourcePathReopened && !image.installedInFEX &&
           !image.executablePagesEnabled && !image.guestCodeExecuted &&
           !image.glibcLoaderExecuted && !image.wineTested);
    CheckStagedSegments(image.main,source.files[0]);
    CheckStagedSegments(image.interpreter,source.files[3]);
    const uint64_t originalEntry=image.main.guestEntry;
    assert(originalEntry!=0);

    assert(FailFromBytes(source.files[0].bytes(),48));
    assert(FailFromBytes(nullptr,0));

    // Only a disposable CI fixture is changed. Host snapshot must not see
    // these in-place edits or later unlink of the source file.
    assert(chmod(file.c_str(),0644)==0);
    int fd=open(file.c_str(),O_RDWR|O_CLOEXEC);
    assert(fd>=0);
    unsigned char originalByte=0;
    assert(pread(fd,&originalByte,1,100)==1);
    unsigned char damaged=originalByte^0x80U;
    assert(pwrite(fd,&damaged,1,100)==1);
    close(fd);
    assert(chmod(file.c_str(),0444)==0);
    FixedGuestSnapshots refused;
    assert(!PinAndCaptureFixedGuest(app.c_str(),refused,why));
    VerifiedSnapshotElfImages again;
    assert(StageFixedMainAndInterpreterFromSnapshots(source,again,why));
    assert(again.main.guestEntry==originalEntry);
    CheckStagedSegments(again.main,source.files[0]);
    CheckStagedSegments(again.interpreter,source.files[3]);
    assert(unlink(file.c_str())==0);
    assert(!PinAndCaptureFixedGuest(app.c_str(),refused,why));
    assert(StageFixedMainAndInterpreterFromSnapshots(source,again,why));
    CheckStagedSegments(again.main,source.files[0]);

    // A default or logically cleared snapshot must fail closed.
    FixedGuestSnapshots blank;
    assert(!StageFixedMainAndInterpreterFromSnapshots(blank,again,why));
    assert(!again.mainFromVerifiedSnapshot && !again.interpreterFromVerifiedSnapshot &&
           again.main.hostView==nullptr && again.interpreter.hostView==nullptr);
    source.reset();
    assert(!StageFixedMainAndInterpreterFromSnapshots(source,again,why));
    std::puts("KERNIX_G2C_PATHLESS_ELF_PTLOAD_FROM_VERIFIED_SNAPSHOT_PASS_NOT_FEX_OR_DEVICE");
    return 0;
}
