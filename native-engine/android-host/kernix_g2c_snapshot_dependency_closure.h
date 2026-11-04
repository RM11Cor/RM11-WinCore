#pragma once
// KERNIX G2-C: explicit four-file x86 ELF resolver backed EXCLUSIVELY by
// previously SHA-256-verified anonymous read-only snapshots. Never opens a
// pathname. No optional rootfs fallback, host /lib, FEX or guest execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2c_native_readonly_guest_snapshots.h"
#include "kernix_guest_elf64_dependency_closure.h"
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace kernix::g2c {
inline bool ResolveFixedGuestSnapshotBytes(
    const FixedGuestSnapshots& source, std::string_view path,
    std::vector<unsigned char>& out) {
    out.clear();
    if (!source.allHashesVerified || source.handedToFEX ||
        source.guestExecuted || source.interpreterExecuted ||
        source.wineTested) return false;
    static constexpr std::array<std::string_view,4> names{{
        "/bin/kernix-dynamic-app",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib64/ld-linux-x86-64.so.2"
    }};
    static constexpr std::array<size_t,4> sizes{{13344,2118168,235408,235408}};
    for (size_t i=0;i<names.size();++i) {
        if (path!=names[i]) continue;
        const auto& bytes=source.files[i];
        if (!bytes.readOnlySnapshot() ||
            !bytes.bytes() || bytes.size()!=sizes[i]) return false;
        out.assign(bytes.bytes(),bytes.bytes()+bytes.size());
        return true;
    }
    return false;
}

inline kernix::g2b::GuestELFBytesResolver FixedGuestSnapshotResolver(
    const FixedGuestSnapshots& source) {
    return [&source](std::string_view path,std::vector<unsigned char>& bytes) {
        return ResolveFixedGuestSnapshotBytes(source,path,bytes);
    };
}

inline bool AuditFixedGuestDependencyClosure(
    const FixedGuestSnapshots& source,
    kernix::g2b::GuestDependencyClosure& closure,std::string& why) {
    closure={};
    if (!source.allHashesVerified) {
        why="G2C_SNAPSHOT_CLOSURE_SOURCE_NOT_ATTESTED";
        return false;
    }
    auto resolver=FixedGuestSnapshotResolver(source);
    if (!kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
            resolver,"/bin/kernix-dynamic-app",closure,why)) {
        closure={};
        return false;
    }
    if (!closure.allDirectAndTransitiveFilesPresent ||
        closure.guestInterpreter!="/lib64/ld-linux-x86-64.so.2" ||
        closure.nodes.size()<3 ||
        closure.guestCodeExecuted || closure.relocationsApplied ||
        closure.symbolVersionsResolved || closure.androidWineTested) {
        closure={};
        why="G2C_SNAPSHOT_CLOSURE_FIXED_INTERPRETER_OR_NODES_REJECTED";
        return false;
    }
    why="none";
    return true;
}
} // namespace kernix::g2c
