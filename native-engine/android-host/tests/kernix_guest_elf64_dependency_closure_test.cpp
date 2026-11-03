#include "kernix_guest_elf64_dependency_closure.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

static void Copy(const char* src, const std::string& dest) {
    int input = open(src, O_RDONLY | O_CLOEXEC);
    assert(input >= 0);
    int output = open(dest.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(output >= 0);
    char buffer[32768];
    ssize_t n = 0;
    while ((n = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < n) {
            ssize_t w = write(output, buffer + offset, static_cast<size_t>(n - offset));
            assert(w > 0);
            offset += w;
        }
    }
    assert(n == 0);
    close(input);
    close(output);
}
static bool Contains(const kernix::g2b::GuestDependencyClosure& c,
                     std::string_view path) {
    return std::any_of(c.nodes.begin(), c.nodes.end(), [&](const auto& node) {
        return node.path == path;
    });
}
static void FailClosed(int root, std::string_view exe) {
    kernix::g2b::GuestDependencyClosure closure;
    std::string reason;
    assert(!kernix::g2b::AuditGuestELFDependencyClosure(
        root, exe, closure, reason));
    assert(reason != "none" && !reason.empty());
    assert(!closure.allDirectAndTransitiveFilesPresent);
    assert(!closure.guestCodeExecuted && !closure.androidWineTested);
}
int main(int argc, char** argv) {
    if (argc != 6) return 2;
    char temp[] = "/tmp/kernix-g2b-closure-XXXXXX";
    char* dir = mkdtemp(temp);
    assert(dir);
    std::string base(dir);
    for (const char* sub : {"/bin", "/lib", "/lib64", "/lib/x86_64-linux-gnu"})
        assert(mkdir((base + sub).c_str(), 0700) == 0);
    const std::string app = base + "/bin/kernix-dynamic-app";
    const std::string loader = base + "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
    const std::string libc = base + "/lib/x86_64-linux-gnu/libc.so.6";
    const std::string mid = base + "/lib/x86_64-linux-gnu/libkernix_mid.so";
    const std::string leaf = base + "/lib/x86_64-linux-gnu/libkernix_leaf.so";
    const std::string linkerPath = base + "/lib64/ld-linux-x86-64.so.2";
    Copy(argv[1], app);
    Copy(argv[2], loader);
    Copy(argv[3], libc);
    Copy(argv[4], mid);
    Copy(argv[5], leaf);
    assert(symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                   linkerPath.c_str()) == 0);
    int root = open(base.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(root >= 0);

    kernix::g2b::GuestDependencyClosure c;
    std::string err;
    bool ok = kernix::g2b::AuditGuestELFDependencyClosure(
        root, "/bin/kernix-dynamic-app", c, err);
    if (!ok) fprintf(stderr, "Closure inspection of real ELF failed: %s\n",
                     err.c_str());
    assert(ok);
    assert(c.allDirectAndTransitiveFilesPresent && c.resolvedEdges >= 3);
    assert(c.guestInterpreter == "/lib64/ld-linux-x86-64.so.2");
    assert(c.nodes.size() >= 5);
    assert(Contains(c, "/bin/kernix-dynamic-app"));
    assert(Contains(c, "/lib64/ld-linux-x86-64.so.2"));
    assert(Contains(c, "/lib/x86_64-linux-gnu/libc.so.6"));
    assert(Contains(c, "/lib/x86_64-linux-gnu/libkernix_mid.so"));
    assert(Contains(c, "/lib/x86_64-linux-gnu/libkernix_leaf.so"));
    assert(!c.guestCodeExecuted && !c.androidWineTested);
    assert(!c.relocationsApplied && !c.symbolVersionsResolved);

    // Removing a transitive dependency must fail even if the first-level
    // direct needed library remains present and has a valid ELF header.
    assert(rename(leaf.c_str(), (leaf + ".hidden").c_str()) == 0);
    FailClosed(root, "/bin/kernix-dynamic-app");
    assert(rename((leaf + ".hidden").c_str(), leaf.c_str()) == 0);

    // Guest-absolute link must not escape into Android/Linux host /etc.
    assert(unlink(leaf.c_str()) == 0);
    assert(symlink("/etc/passwd", leaf.c_str()) == 0);
    FailClosed(root, "/bin/kernix-dynamic-app");
    assert(unlink(leaf.c_str()) == 0);
    Copy(argv[5], leaf);

    // Corrupt a real x86-64 DSO machine ID and require closure rejection.
    int fd = open(leaf.c_str(), O_WRONLY | O_CLOEXEC);
    assert(fd >= 0);
    const unsigned char invalidMachine[2] = {0, 0};
    assert(pwrite(fd, invalidMachine, sizeof(invalidMachine), 18) == 2);
    close(fd);
    FailClosed(root, "/bin/kernix-dynamic-app");
    assert(unlink(leaf.c_str()) == 0);
    Copy(argv[5], leaf);

    // Do not substitute host absolute dynamic loader if guest link is gone.
    assert(rename(linkerPath.c_str(), (linkerPath + ".hidden").c_str()) == 0);
    FailClosed(root, "/bin/kernix-dynamic-app");
    assert(rename((linkerPath + ".hidden").c_str(), linkerPath.c_str()) == 0);

    FailClosed(root, "/bin/../bin/kernix-dynamic-app");
    FailClosed(root, "/bin/not-found");
    assert(fcntl(root, F_GETFD) >= 0);
    close(root);
    for (const auto& p : {app,loader,libc,mid,leaf,linkerPath})
        assert(unlink(p.c_str()) == 0);
    for (const char* sub : {"/bin", "/lib64", "/lib/x86_64-linux-gnu", "/lib"})
        assert(rmdir((base + sub).c_str()) == 0);
    assert(rmdir(base.c_str()) == 0);
    puts("KERNIX_G2B_REAL_X86_ELF64_TRANSITIVE_DEPENDENCY_CLOSURE_PASS_NOT_ANDROID_WINE");
    return 0;
}
