#include "kernix_guest_rootfs_symlinks.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

static void put(const std::string& p, const char* content) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(write(fd, content, strlen(content)) == (ssize_t)strlen(content));
    close(fd);
}
static std::string contents(int root, std::string_view guest) {
    int fd = kernix::g2b::OpenGuestFileWithScopedSymlinks(root, guest);
    assert(fd >= 0);
    std::array<char, 128> data {};
    ssize_t n = read(fd, data.data(), data.size());
    assert(n > 0);
    close(fd);
    return std::string(data.data(), static_cast<size_t>(n));
}
static void rejected(int root, std::string_view guest) {
    int fd = kernix::g2b::OpenGuestFileWithScopedSymlinks(root, guest);
    assert(fd == -1);
}
int main() {
    char tmp[] = "/tmp/kernix-g2b-linkscope-XXXXXX";
    char* rootname = mkdtemp(tmp);
    assert(rootname);
    std::string r = rootname;
    auto mkdir_in = [&](const std::string& rel) {
        assert(mkdir((r+rel).c_str(), 0700) == 0);
    };
    mkdir_in("/lib");
    mkdir_in("/lib/x86_64-linux-gnu");
    mkdir_in("/usr");
    mkdir_in("/usr/lib");
    mkdir_in("/usr/lib/wine");
    mkdir_in("/etc");
    put(r+"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "PINNED_GUEST_LOADER");
    put(r+"/usr/lib/wine/kernel32.dll", "PINNED_GUEST_KERNEL32");
    put(r+"/etc/passwd", "INSIDE_APP_ROOT_ONLY");
    assert(symlink("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                   (r+"/lib64").c_str()) == 0);
    assert(symlink("../wine/kernel32.dll", (r+"/usr/lib/wine/relative.dll").c_str()) == 0);
    assert(symlink("/etc/passwd", (r+"/usr/lib/wine/guest-etc").c_str()) == 0);
    assert(symlink("../../../../etc/passwd", (r+"/usr/lib/wine/over-root").c_str()) == 0);
    assert(symlink("/not-in-root", (r+"/usr/lib/wine/not-in-root").c_str()) == 0);
    assert(symlink("/usr/lib/wine/loop2", (r+"/usr/lib/wine/loop1").c_str()) == 0);
    assert(symlink("/usr/lib/wine/loop1", (r+"/usr/lib/wine/loop2").c_str()) == 0);
    assert(symlink("/proc/self/fd/0", (r+"/usr/lib/wine/proc-trap").c_str()) == 0);
    assert(symlink("/usr/lib/wine/kernel32.dll", (r+"/usr/lib/wine/absolute.dll").c_str()) == 0);
    int rootfd = open(r.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(rootfd >= 0);

    assert(contents(rootfd, "/lib64") == "PINNED_GUEST_LOADER");
    assert(contents(rootfd, "/usr/lib/wine/kernel32.dll") == "PINNED_GUEST_KERNEL32");
    assert(contents(rootfd, "/usr/lib/wine/relative.dll") == "PINNED_GUEST_KERNEL32");
    assert(contents(rootfd, "/usr/lib/wine/absolute.dll") == "PINNED_GUEST_KERNEL32");
    assert(contents(rootfd, "/usr/lib/wine/guest-etc") == "INSIDE_APP_ROOT_ONLY");
    for (std::string_view bad : {
        "", "/", "/usr/lib/wine/../kernel32.dll", "/usr/lib/wine/./kernel32.dll",
        "/usr//lib/wine/kernel32.dll", "/usr/lib/wine/",
        "/usr/lib/wine/over-root", "/usr/lib/wine/not-in-root",
        "/usr/lib/wine/loop1", "/usr/lib/wine/proc-trap",
        "/usr/lib/wine", "usr/lib/wine/kernel32.dll",
        "/usr/lib/wine/missing.dll", "/usr/lib/wine\\kernel32.dll",
        "/tmp/kernix-g2b-linkscope-fake",
        "/lib/x86_64-linux-gnu/../etc/passwd"
    }) rejected(rootfd, bad);
    assert(fcntl(rootfd, F_GETFD) >= 0);
    close(rootfd);
    unlink((r+"/lib64").c_str());
    for (const char* filename : {"relative.dll", "guest-etc", "over-root",
            "not-in-root", "loop1", "loop2", "proc-trap", "absolute.dll", "kernel32.dll"})
        unlink((r+"/usr/lib/wine/"+filename).c_str());
    unlink((r+"/etc/passwd").c_str());
    unlink((r+"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2").c_str());
    rmdir((r+"/usr/lib/wine").c_str());
    rmdir((r+"/usr/lib").c_str());
    rmdir((r+"/usr").c_str());
    rmdir((r+"/lib/x86_64-linux-gnu").c_str());
    rmdir((r+"/lib").c_str());
    rmdir((r+"/etc").c_str());
    rmdir(r.c_str());
    std::puts("KERNIX_G2B_GUEST_ROOTFS_SCOPED_LINUX_SYMLINKS_PASS_NOT_ANDROID_WINE");
}
