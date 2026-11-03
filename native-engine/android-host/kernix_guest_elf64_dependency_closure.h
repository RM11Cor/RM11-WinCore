#pragma once
// KERNIX G2-B: fail-closed, read-only recursive DT_NEEDED inventory of
// x86-64 ELF objects inside an app-owned immutable Linux guest rootfs.
// This is NOT a guest dynamic loader or FEX/Wine process execution.
// SPDX-License-Identifier: MIT
#include "kernix_guest_elf64_dynamic_audit.h"
#include <deque>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kernix::g2b {
constexpr size_t kMaxClosureObjects = 32;
constexpr size_t kMaxClosureEdges = 192;

struct GuestDependencyNode {
    std::string path;
    std::vector<std::string> needed;
    std::vector<std::string> resolvedDirectLibraries;
};

struct GuestDependencyClosure {
    std::string guestExecutable;
    std::string guestInterpreter;
    std::vector<GuestDependencyNode> nodes;
    size_t resolvedEdges = 0;
    bool allDirectAndTransitiveFilesPresent = false;
    bool symbolVersionsResolved = false;
    bool relocationsApplied = false;
    bool guestCodeExecuted = false;
    bool androidWineTested = false;
};

// The first entry MUST be the executable. Shared libraries and the dynamic
// interpreter are parsed with PT_INTERP forbidden: a library cannot silently
// impersonate a top-level executable. Cycles are handled by path-based
// visited bookkeeping, with finite caps to stop path alias amplification.
// A pass means only that the named ELF objects form a read-only file graph.
// It does NOT mean that the guest loader will resolve ABI/symbol versions,
// RPATH, relocations, TLS, IFUNC or any host syscall needed by glibc.
inline bool AuditGuestELFDependencyClosure(int root,
                                           std::string_view guestExecutable,
                                           GuestDependencyClosure& result,
                                           std::string& error) {
    result = {};
    if (guestExecutable.size() < 2 ||
        guestExecutable.front() != '/' ||
        guestExecutable.size() > kMaxSymlinkGuestPath)
    {
        error = "BAD_GUEST_EXECUTABLE_PATH";
        return false;
    }
    std::deque<std::string> pending{std::string(guestExecutable)};
    std::set<std::string> visited;
    size_t edges = 0;
    std::string interpreter;
    while (!pending.empty()) {
        const std::string path = std::move(pending.front());
        pending.pop_front();
        if (visited.find(path) != visited.end()) continue;
        if (visited.size() >= kMaxClosureObjects) {
            error = "GUEST_ELF_DEPENDENCY_OBJECT_LIMIT";
            result = {};
            return false;
        }
        const bool isMain = visited.empty();
        GuestDynamicAudit item;
        std::string failure;
        if (!AuditGuestDynamicELF(root, path, item, failure, isMain)) {
            error = "GUEST_ELF_DEPENDENCY_FAILURE:" + path + ":" + failure;
            result = {};
            return false;
        }
        visited.insert(path);
        if (isMain) {
            interpreter = item.interpreter;
            if (interpreter.empty()) {
                error = "GUEST_ELF_INTERPRETER_MISSING";
                result = {};
                return false;
            }
        }
        // Some real guest DSOs, including glibc libc.so.6, contain their
        // own PT_INTERP. Interpret all such paths only within guest rootfs.
        if (!item.interpreter.empty())
            pending.push_back(item.interpreter);
        if (item.resolvedDirectLibraries.size() != item.needed.size() ||
            edges > kMaxClosureEdges - item.needed.size()) {
            error = "GUEST_ELF_DEPENDENCY_EDGE_LIMIT";
            result = {};
            return false;
        }
        edges += item.needed.size();
        for (const auto& dep : item.resolvedDirectLibraries) {
            if (dep.size() > kMaxSymlinkGuestPath) {
                error = "GUEST_ELF_DEPENDENCY_PATH_TOO_LONG";
                result = {};
                return false;
            }
            if (visited.find(dep) == visited.end())
                pending.push_back(dep);
        }
        if (pending.size() > kMaxClosureEdges + kMaxClosureObjects) {
            error = "GUEST_ELF_DEPENDENCY_QUEUE_LIMIT";
            result = {};
            return false;
        }
        result.nodes.push_back({path, std::move(item.needed),
                                std::move(item.resolvedDirectLibraries)});
    }
    result.guestExecutable = std::string(guestExecutable);
    result.guestInterpreter = std::move(interpreter);
    result.resolvedEdges = edges;
    result.allDirectAndTransitiveFilesPresent = true;
    error = "none";
    return true;
}
}
