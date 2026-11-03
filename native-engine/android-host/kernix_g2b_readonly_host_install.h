#pragma once
// KERNIX G2-B: copy fixed, source-inspected x86 ELF PT_LOAD and process
// stack bytes into previously RESERVED host windows. No FEX, no guest RIP/RSP,
// no host PROT_EXEC, no MAP_FIXED, and no Windows/Wine execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2b_guest_host_reservations.h"
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace kernix::g2b {

// This requires an app-owned immutable rootfs and freshly acquired windows.
// Only applies to actual 4K/16K Linux/Android host pages, with each window
// a whole number of host pages; this keeps guard pages inaccessible when
// guest and host page sizes differ. The windows remain live and readable
// ONLY for the lifetime of X86HostReservedGuestLaunch.
inline bool StageX86ReadonlyHostBytes(
    int rootfd, X86HostReservedGuestLaunch& launch, std::string& error) {
    const auto fail=[&](const char* why)->bool {
        launch.release();   // removes any temporary PROT_READ|PROT_WRITE
        error=why;
        return false;
    };
    if (rootfd<0 || !launch.hostVAsReservedPROT_NONE ||
        launch.hostImageBytesStagedReadonly ||
        launch.hostStackBytesStagedReadonly ||
        launch.guestVAsInstalledInFEX ||
        launch.executableGuestPagesMapped ||
        launch.guestCodeExecuted ||
        launch.androidWineTested ||
        !launch.plan.stackAndAuxvConsistent ||
        !launch.plan.guestVirtualAddressesValidated ||
        launch.plan.stack.guestMemoryMapped ||
        launch.plan.stack.guestCodeExecuted)
        return fail("HOST_STAGE_LAUNCH_NOT_FRESH_OR_INVALID");
    const long actual=sysconf(_SC_PAGESIZE);
    if (actual!=4096 && actual!=16384)
        return fail("HOST_STAGE_HOST_PAGES_UNSUPPORTED");
    const uint64_t hostPage=static_cast<uint64_t>(actual);
    const auto windowAligned=[&](const X86HostNoAccessReservation& w) {
        return w.hostMapping && w.guestStart &&
               w.guestStart%hostPage==0 &&
               w.guestBytes%hostPage==0 &&
               w.guestBytes>=hostPage &&
               !w.isFEXGuestAddressSpace && !w.executable &&
               !w.usedMAP_FIXED && w.noAccess;
    };
    if (!windowAligned(launch.main) ||
        !windowAligned(launch.interpreter) ||
        !windowAligned(launch.stack))
        return fail("HOST_STAGE_UNALIGNED_RESERVATION_GUARD_PROTECTION");
    if (launch.plan.stack.bytes.size()!=launch.stack.guestBytes ||
        launch.plan.stack.guestBottom!=launch.stack.guestStart)
        return fail("HOST_STAGE_STACK_NOT_IN_RESERVED_WINDOW");

    GuestReadonlyImage main,loader;
    std::string why;
    if (!StageReadOnlyGuestELFImage(
            rootfd,launch.plan.guestExecutable,main,why,true) ||
        !StageReadOnlyGuestELFImage(
            rootfd,launch.plan.guestInterpreter,loader,why,false) ||
        !main.hostView || !loader.hostView ||
        !main.hostViewReadOnly || !loader.hostViewReadOnly ||
        main.hostViewExecutable || loader.hostViewExecutable ||
        main.guestCodeExecuted || loader.guestCodeExecuted ||
        main.relocationsApplied || loader.relocationsApplied ||
        main.hostViewBytes!=launch.main.guestBytes ||
        loader.hostViewBytes!=launch.interpreter.guestBytes ||
        launch.plan.mainLoadBias!=
          launch.main.guestStart-main.guestPageAlignedBase ||
        launch.plan.interpreterLoadBias!=
          launch.interpreter.guestStart-loader.guestPageAlignedBase)
        return fail("HOST_STAGE_GUEST_ELF_SNAPSHOT_OR_LAYOUT_MISMATCH");
    const auto stage=[&](const GuestReadonlyImage& image,
                         const X86HostNoAccessReservation& w)->bool {
        void* addr=reinterpret_cast<void*>(
            static_cast<uintptr_t>(w.guestStart));
        if (mprotect(addr,static_cast<size_t>(w.guestBytes),
                     PROT_READ|PROT_WRITE)!=0)
            return false;
        // No raw copy from untrusted file pointers: StageReadOnlyGuestELFImage
        // has already validated PT_LOAD offsets, BSS and image size.
        std::memcpy(addr,image.hostView,static_cast<size_t>(w.guestBytes));
        if (mprotect(addr,static_cast<size_t>(w.guestBytes),PROT_READ)!=0)
            return false;
        return std::memcmp(addr,image.hostView,
                           static_cast<size_t>(w.guestBytes))==0;
    };
    if (!stage(main,launch.main))
        return fail("HOST_STAGE_MAIN_READONLY_TRANSITION_FAILED");
    if (!stage(loader,launch.interpreter))
        return fail("HOST_STAGE_INTERPRETER_READONLY_TRANSITION_FAILED");
    void* stackaddr=reinterpret_cast<void*>(
        static_cast<uintptr_t>(launch.stack.guestStart));
    if (mprotect(stackaddr,static_cast<size_t>(launch.stack.guestBytes),
                 PROT_READ|PROT_WRITE)!=0)
        return fail("HOST_STAGE_STACK_TEMP_WRITE_FAILED");
    std::memcpy(stackaddr,launch.plan.stack.bytes.data(),
                launch.plan.stack.bytes.size());
    if (mprotect(stackaddr,static_cast<size_t>(launch.stack.guestBytes),
                 PROT_READ)!=0)
        return fail("HOST_STAGE_STACK_READONLY_TRANSITION_FAILED");
    if (std::memcmp(stackaddr,launch.plan.stack.bytes.data(),
                    launch.plan.stack.bytes.size())!=0)
        return fail("HOST_STAGE_STACK_CONTENT_MISMATCH");
    // No executable guest pages were enabled, and the x86 RIP/RSP values
    // are NOT passed to FEX. A readonly view cannot run a Linux linker.
    launch.hostImageBytesStagedReadonly=true;
    launch.hostStackBytesStagedReadonly=true;
    error="none";
    return true;
}
} // namespace kernix::g2b
