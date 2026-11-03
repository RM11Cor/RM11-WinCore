#include "kernix_guest_elf64_readonly_image.h"
#include <elf.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static void copyFile(const char* source, const std::string& dest) {
    int input = open(source, O_RDONLY | O_CLOEXEC);
    assert(input >= 0);
    int output = open(dest.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(output >= 0);
    char buf[16384];
    ssize_t n;
    while ((n = read(input, buf, sizeof(buf))) > 0) {
        ssize_t pos = 0;
        while (pos < n) {
            ssize_t written = write(output, buf + pos,
                                    static_cast<size_t>(n-pos));
            assert(written > 0);
            pos += written;
        }
    }
    assert(n == 0);
    close(input);
    close(output);
}
static void rejected(int root, const char* path,
                     kernix::g2b::GuestReadonlyImage& image) {
    std::string reason;
    assert(!kernix::g2b::StageReadOnlyGuestELFImage(
        root, path, image, reason));
    assert(reason != "none" && !reason.empty());
    assert(!image.hostView && !image.hostViewReadOnly &&
           !image.guestCodeExecuted && !image.hostViewExecutable);
}
static void inspect(int root, const char* path, bool isMain) {
    kernix::g2b::GuestReadonlyImage image;
    std::string reason;
    if (!kernix::g2b::StageReadOnlyGuestELFImage(
            root, path, image, reason, isMain)) {
        fprintf(stderr,"G2B real ELF image mapping rejected: %s\n",reason.c_str());
        abort();
    }
    assert(image.hostView && image.hostViewBytes >= 4096);
    assert(image.hostViewReadOnly && !image.hostViewExecutable &&
           !image.guestCodeExecuted && !image.relocationsApplied);
    assert(!image.androidWineTested && !image.segments.empty());
    int fd = kernix::g2b::OpenGuestFileWithScopedSymlinks(root, path);
    assert(fd >= 0);
    bool compared = false, bss = false;
    for (const auto& segment : image.segments) {
        assert(!(segment.guestFlags & PF_W) || !(segment.guestFlags & PF_X));
        if (segment.fileBytes) {
            size_t count = static_cast<size_t>(segment.fileBytes);
            std::vector<char> original(count);
            assert(pread(fd,original.data(),count,segment.fileOffset) ==
                   static_cast<ssize_t>(count));
            const char* mapped = static_cast<const char*>(image.hostView) +
                                 segment.guestVaddr - image.guestPageAlignedBase;
            assert(memcmp(mapped,original.data(),count) == 0);
            compared = true;
        }
        if (segment.memoryBytes > segment.fileBytes) {
            const char* tail = static_cast<const char*>(image.hostView) +
                               segment.guestVaddr - image.guestPageAlignedBase +
                               segment.fileBytes;
            for (size_t i = 0; i < segment.memoryBytes - segment.fileBytes; ++i)
                assert(tail[i] == 0);
            bss = true;
        }
    }
    assert(compared);
    if (isMain) assert(image.guestEntry != 0);
    (void)bss;
    close(fd);
}
int main(int argc, char** argv) {
    if (argc != 4) return 2;
    char tmp[] = "/tmp/kernix-g2b-elf-roview-XXXXXX";
    char* root = mkdtemp(tmp);
    assert(root);
    const std::string base(root);
    assert(mkdir((base+"/bin").c_str(),0700) == 0);
    assert(mkdir((base+"/lib").c_str(),0700) == 0);
    assert(mkdir((base+"/lib/x86_64-linux-gnu").c_str(),0700) == 0);
    const std::string exe=base+"/bin/test-guest";
    const std::string libc=base+"/lib/x86_64-linux-gnu/libc.so.6";
    const std::string loader=base+"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
    copyFile(argv[1],exe);
    copyFile(argv[2],libc);
    copyFile(argv[3],loader);
    int fd=open(base.c_str(),O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC);
    assert(fd>=0);
    inspect(fd,"/bin/test-guest",true);
    inspect(fd,"/lib/x86_64-linux-gnu/libc.so.6",false);
    inspect(fd,"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",false);
    kernix::g2b::GuestReadonlyImage image;
    rejected(fd,"/bin/../bin/test-guest",image);
    rejected(fd,"/bin/missing",image);
    int patch=open(exe.c_str(),O_RDWR|O_CLOEXEC);
    assert(patch>=0);
    Elf64_Ehdr h{};
    assert(pread(patch,&h,sizeof(h),0)==sizeof(h));
    Elf64_Phdr first{};
    assert(pread(patch,&first,sizeof(first),h.e_phoff)==sizeof(first));
    // Find an actual PT_LOAD, corrupt flags to W|X and test fail-closed.
    for (unsigned i=0;i<h.e_phnum;i++) {
        Elf64_Phdr ph{};
        const off_t offset=h.e_phoff+static_cast<off_t>(i)*sizeof(ph);
        assert(pread(patch,&ph,sizeof(ph),offset)==sizeof(ph));
        if (ph.p_type != PT_LOAD) continue;
        const uint32_t bad=PF_R|PF_W|PF_X;
        assert(pwrite(patch,&bad,sizeof(bad),
                      offset+offsetof(Elf64_Phdr,p_flags))==sizeof(bad));
        rejected(fd,"/bin/test-guest",image);
        assert(pwrite(patch,&ph.p_flags,sizeof(ph.p_flags),
                      offset+offsetof(Elf64_Phdr,p_flags))==sizeof(ph.p_flags));
        break;
    }
    close(patch);
    close(fd);
    unlink(exe.c_str()); unlink(libc.c_str()); unlink(loader.c_str());
    rmdir((base+"/bin").c_str());
    rmdir((base+"/lib/x86_64-linux-gnu").c_str());
    rmdir((base+"/lib").c_str());
    rmdir(base.c_str());
    puts("KERNIX_G2B_REAL_ELF_PT_LOAD_READONLY_ANON_IMAGE_AND_WX_REJECTION_PASS_NO_GUEST_EXECUTION");
}
