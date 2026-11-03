#include "kernix_guest_rootfs_readonly.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    char temp[] = "/tmp/kernix-g2b-rootfs-XXXXXX";
    char *root = mkdtemp(temp);
    assert(root);
    const auto make = [&](const std::string &sub) {
        assert(mkdir((std::string(root) + sub).c_str(), 0700) == 0);
    };
    make("/usr"); make("/usr/lib"); make("/usr/lib/wine");
    const std::string good = std::string(root) + "/usr/lib/wine/kernel32.dll";
    int w = open(good.c_str(), O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0600);
    assert(w >= 0);
    const char fixture[] = "PE-data-reference";
    assert(write(w, fixture, sizeof(fixture)) == sizeof(fixture));
    close(w);
    const int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(rootfd >= 0);
    int fd = kernix::g2b::OpenReadOnlyGuestRegularFile(rootfd, "/usr/lib/wine/kernel32.dll");
    assert(fd >= 0);
    std::array<char, 64> readbuf{};
    assert(read(fd, readbuf.data(), readbuf.size()) == sizeof(fixture));
    assert(std::strcmp(readbuf.data(), fixture) == 0);
    close(fd);
    const std::string escape = std::string(root) + "/usr/lib/wine/escape.dll";
    assert(symlink("/etc/passwd", escape.c_str()) == 0);
    const std::string linkdir = std::string(root) + "/usr/lib/host-shadow";
    assert(symlink("/etc", linkdir.c_str()) == 0);
    for (std::string_view bad : {
            "", "/", "usr/lib/wine/kernel32.dll", "//usr/lib/wine/kernel32.dll",
            "/usr//lib/wine/kernel32.dll", "/usr/lib/wine/../kernel32.dll",
            "/usr/lib/wine/./kernel32.dll", "/usr/lib/wine/", "../../etc/passwd",
            "/usr/lib/wine/escape.dll", "/usr/lib/host-shadow/passwd",
            "/etc/passwd", "/usr/lib/wine/missing.dll", "/usr/lib/wine\\kernel32.dll"}) {
        assert(kernix::g2b::OpenReadOnlyGuestRegularFile(rootfd, bad) < 0);
    }
    assert(kernix::g2b::OpenReadOnlyGuestRegularFile(rootfd, "/usr/lib/wine") < 0);
    assert(fcntl(rootfd, F_GETFD) >= 0);
    close(rootfd);
    unlink(escape.c_str()); unlink(linkdir.c_str()); unlink(good.c_str());
    rmdir((std::string(root) + "/usr/lib/wine").c_str());
    rmdir((std::string(root) + "/usr/lib").c_str());
    rmdir((std::string(root) + "/usr").c_str());
    rmdir(root);
    std::puts("KERNIX_G2B_GUEST_ROOTFS_READONLY_SYMLINK_TRAVERSAL_GUARD_PASS_NOT_ANDROID_WINE");
}
