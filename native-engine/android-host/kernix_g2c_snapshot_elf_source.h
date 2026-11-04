#pragma once
// KERNIX G2-C: use EXACTLY the previously SHA-256-verified anonymous ELF
// snapshots as PT_LOAD sources. No path reopen or source FD consumption here.
// A staged host PROT_READ image is not a FEX context or Android execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_guest_elf64_readonly_image.h"
#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace kernix::g2c {

struct VerifiedSnapshotElfImages {
    kernix::g2b::GuestReadonlyImage main;
    kernix::g2b::GuestReadonlyImage interpreter;
    bool mainFromVerifiedSnapshot = false;
    bool interpreterFromVerifiedSnapshot = false;
    bool sourcePathReopened = false;
    bool installedInFEX = false;
    bool executablePagesEnabled = false;
    bool guestCodeExecuted = false;
    bool glibcLoaderExecuted = false;
    bool wineTested = false;
    void reset() {
        main.release();
        interpreter.release();
        mainFromVerifiedSnapshot = false;
        interpreterFromVerifiedSnapshot = false;
        sourcePathReopened = false;
        installedInFEX = false;
        executablePagesEnabled = false;
        guestCodeExecuted = false;
        glibcLoaderExecuted = false;
        wineTested = false;
    }
};

inline bool StageFixedMainAndInterpreterFromSnapshots(
    const FixedGuestSnapshots& source, VerifiedSnapshotElfImages& out,
    std::string& why) {
    out.reset();
    if (!source.allHashesVerified ||
        source.handedToFEX || source.guestExecuted ||
        source.interpreterExecuted || source.wineTested ||
        !source.files[0].readOnlySnapshot() ||
        !source.files[2].readOnlySnapshot() ||
        !source.files[3].readOnlySnapshot() ||
        source.files[0].size()!=13344 ||
        source.files[2].size()!=235408 ||
        source.files[3].size()!=235408) {
        why = "G2C_ELF_SNAPSHOT_NOT_VERIFIED_OR_BAD_SHAPE";
        return false;
    }
    // The fixed loader is physically duplicated in the original guest tree
    // to satisfy /lib64/ld-linux-x86-64.so.2 without host symlinks.
    // Using index 3 is required by the exact PT_INTERP; compare with index 2.
    const auto loaderA=std::span<const unsigned char>(
        source.files[2].bytes(),source.files[2].size());
    const auto loaderB=std::span<const unsigned char>(
        source.files[3].bytes(),source.files[3].size());
    if (!std::equal(loaderA.begin(),loaderA.end(),loaderB.begin())) {
        why = "G2C_ELF_INTERPRETER_SNAPSHOT_DUPLICATE_MISMATCH";
        return false;
    }
    const auto main=std::span<const unsigned char>(
        source.files[0].bytes(),source.files[0].size());
    if (!kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
            main,out.main,why,true) ||
        !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
            loaderB,out.interpreter,why,false) ||
        !out.main.hostViewReadOnly || !out.interpreter.hostViewReadOnly ||
        out.main.hostViewExecutable || out.interpreter.hostViewExecutable ||
        out.main.guestCodeExecuted || out.interpreter.guestCodeExecuted) {
        out.reset();
        return false;
    }
    out.mainFromVerifiedSnapshot = true;
    out.interpreterFromVerifiedSnapshot = true;
    why = "none";
    return true;
}
} // namespace kernix::g2c
