// Real x86_64 ELF/PT_INTERP/DT_NEEDED inputs. Test ONLY reads bytes;
 // never executes the fixture, guest loader or any Windows PE.
#include "kernix_guest_elf64_dynamic_audit.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

static void copyFile(const char* src, const std::string& target) {
    int from = open(src, O_RDONLY | O_CLOEXEC);
    assert(from >= 0);
    int into = open(target.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(into >= 0);
    char chunk[16384];
    ssize_t n;
    while ((n = read(from, chunk, sizeof(chunk))) > 0) {
        ssize_t done = 0;
        while (done < n) {
            const ssize_t w = write(into, chunk + done, n - done);
            assert(w > 0);
            done += w;
        }
    }
    assert(n == 0);
    close(from); close(into);
}
static void rejected(int root, std::string_view guest) {
    kernix::g2b::GuestDynamicAudit result;
    std::string error;
    assert(!kernix::g2b::AuditGuestDynamicELF(root, guest, result, error));
    assert(!error.empty());
    assert(!result.guestCodeExecuted && !result.androidWineTested);
}
int main(int argc, char** argv) {
    if (argc != 4) return 2;
    char tmp[] = "/tmp/kernix-g2b-dynamic-audit-XXXXXX";
    char* base = mkdtemp(tmp);
    assert(base);
    const std::string root(base);
    auto mkdirIn = [&](std::string_view name) {
        assert(mkdir((root + std::string(name)).c_str(), 0700) == 0);
    };
    mkdirIn("/bin"); mkdirIn("/lib"); mkdirIn("/lib64");
    mkdirIn("/lib/x86_64-linux-gnu");
    copyFile(argv[1], root + "/bin/kernix-elf64-guest");
    copyFile(argv[2], root + "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    copyFile(argv[3], root + "/lib/x86_64-linux-gnu/libc.so.6");
    assert(symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                   (root + "/lib64/ld-linux-x86-64.so.2").c_str()) == 0);
    int rootfd = open(root.c_str(),
                      O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(rootfd >= 0);
    kernix::g2b::GuestDynamicAudit result;
    std::string error;
    bool ok = kernix::g2b::AuditGuestDynamicELF(
        rootfd, "/bin/kernix-elf64-guest", result, error);
    if (!ok) fprintf(stderr, "Real x86 ELF inspection failed: %s\n",
                     error.c_str());
    assert(ok);
    assert(result.interpreter == "/lib64/ld-linux-x86-64.so.2");
    assert(result.needed.size() == 1 && result.needed[0] == "libc.so.6");
    assert(result.resolvedDirectLibraries.size() == 1 &&
           result.resolvedDirectLibraries[0] ==
               "/lib/x86_64-linux-gnu/libc.so.6");
    assert(result.readOnly && !result.executableLoaded &&
           !result.guestCodeExecuted && !result.androidWineTested);
    rejected(rootfd, "/bin/../bin/kernix-elf64-guest");
    rejected(rootfd, "/bin/missing");
    assert(rename((root + "/lib/x86_64-linux-gnu/libc.so.6").c_str(),
                  (root + "/lib/x86_64-linux-gnu/libc.so.6.hidden").c_str()) == 0);
    rejected(rootfd, "/bin/kernix-elf64-guest");
    assert(symlink("/etc/passwd",
                   (root + "/lib/x86_64-linux-gnu/libc.so.6").c_str()) == 0);
    rejected(rootfd, "/bin/kernix-elf64-guest");
    unlink((root + "/lib/x86_64-linux-gnu/libc.so.6").c_str());
    assert(rename((root + "/lib/x86_64-linux-gnu/libc.so.6.hidden").c_str(),
                  (root + "/lib/x86_64-linux-gnu/libc.so.6").c_str()) == 0);
    assert(rename((root + "/lib64/ld-linux-x86-64.so.2").c_str(),
                  (root + "/lib64/ld-linux-x86-64.so.2.hidden").c_str()) == 0);
    rejected(rootfd, "/bin/kernix-elf64-guest");
    assert(rename((root + "/lib64/ld-linux-x86-64.so.2.hidden").c_str(),
                  (root + "/lib64/ld-linux-x86-64.so.2").c_str()) == 0);
    int bad = open((root + "/bin/kernix-elf64-guest").c_str(), O_WRONLY);
    assert(bad >= 0);
    const unsigned char wrongArch[2] = {0,0};
    assert(pwrite(bad, wrongArch, sizeof(wrongArch), 18) == 2);
    close(bad);
    rejected(rootfd, "/bin/kernix-elf64-guest");
    assert(fcntl(rootfd, F_GETFD) >= 0);
    close(rootfd);
    unlink((root + "/lib64/ld-linux-x86-64.so.2").c_str());
    unlink((root + "/bin/kernix-elf64-guest").c_str());
    unlink((root + "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2").c_str());
    unlink((root + "/lib/x86_64-linux-gnu/libc.so.6").c_str());
    rmdir((root + "/bin").c_str());
    rmdir((root + "/lib64").c_str());
    rmdir((root + "/lib/x86_64-linux-gnu").c_str());
    rmdir((root + "/lib").c_str());
    rmdir(root.c_str());
    std::puts("KERNIX_G2B_REAL_ELF64_INTERP_AND_DT_NEEDED_SCOPED_ROOTFS_AUDIT_PASS_NOT_ANDROID_WINE");
}
