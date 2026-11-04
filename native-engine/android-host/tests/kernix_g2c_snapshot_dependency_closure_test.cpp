// G2-C immutable metadata proof: original x86 ELF dependency graph must be
// identical to rootfs baseline, but accessible solely from anonymous memory
// after source mutation/deletion. No FEX execution or dynamic linking.
#include "kernix_g2c_snapshot_dependency_closure.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using kernix::g2c::FixedGuestSnapshots;
using kernix::g2c::PinAndCaptureFixedGuest;
using kernix::g2c::AuditFixedGuestDependencyClosure;
using kernix::g2b::GuestDependencyClosure;

static bool SameGraph(const GuestDependencyClosure& a,
                      const GuestDependencyClosure& b) {
    if (a.guestExecutable!=b.guestExecutable ||
        a.guestInterpreter!=b.guestInterpreter ||
        a.resolvedEdges!=b.resolvedEdges ||
        a.nodes.size()!=b.nodes.size()) return false;
    for(size_t i=0;i<a.nodes.size();++i) {
        if (a.nodes[i].path!=b.nodes[i].path ||
            a.nodes[i].needed!=b.nodes[i].needed ||
            a.nodes[i].resolvedDirectLibraries!=
              b.nodes[i].resolvedDirectLibraries) return false;
    }
    return true;
}

int main(int argc,char** argv) {
    if (argc!=2 || !argv[1] || argv[1][0]!='/') return 2;
    const std::string app(argv[1]);
    const std::string root=app+
      "/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1";
    const int rootfd=open(root.c_str(),O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    assert(rootfd>=0);
    GuestDependencyClosure disk;
    std::string why;
    assert(kernix::g2b::AuditGuestELFDependencyClosure(
        rootfd,"/bin/kernix-dynamic-app",disk,why));
    close(rootfd);

    FixedGuestSnapshots fixed;
    assert(PinAndCaptureFixedGuest(app.c_str(),fixed,why));
    GuestDependencyClosure memory;
    assert(AuditFixedGuestDependencyClosure(fixed,memory,why));
    assert(SameGraph(disk,memory));
    assert(memory.nodes.size()>=3);
    assert(memory.guestInterpreter=="/lib64/ld-linux-x86-64.so.2");

    const auto fetch=kernix::g2c::FixedGuestSnapshotResolver(fixed);
    std::vector<unsigned char> bytes;
    assert(!fetch("/etc/passwd",bytes) && bytes.empty());
    assert(!fetch("/usr/lib/x86_64-linux-gnu/libc.so.6",bytes));
    assert(fetch("/lib64/ld-linux-x86-64.so.2",bytes));
    assert(bytes.size()==235408);
    bytes.clear();
    assert(fetch("/bin/kernix-dynamic-app",bytes));
    assert(bytes.size()==13344);

    // Source corruption + removal after the snapshot cannot influence
    // PT_INTERP or transitive DT_NEEDED audit, nor introduce a fallback.
    const std::string libc=root+"/lib/x86_64-linux-gnu/libc.so.6";
    assert(chmod(libc.c_str(),0644)==0);
    int fd=open(libc.c_str(),O_RDWR|O_CLOEXEC);
    assert(fd>=0);
    unsigned char before=0;
    assert(pread(fd,&before,1,123)==1);
    const unsigned char tampered=before^0x40;
    assert(pwrite(fd,&tampered,1,123)==1);
    close(fd);
    assert(chmod(libc.c_str(),0444)==0);
    FixedGuestSnapshots altered;
    assert(!PinAndCaptureFixedGuest(app.c_str(),altered,why));
    GuestDependencyClosure afterChange;
    assert(AuditFixedGuestDependencyClosure(fixed,afterChange,why));
    assert(SameGraph(memory,afterChange));
    assert(unlink(libc.c_str())==0);
    assert(AuditFixedGuestDependencyClosure(fixed,afterChange,why));
    assert(SameGraph(memory,afterChange));
    assert(!PinAndCaptureFixedGuest(app.c_str(),altered,why));

    GuestDependencyClosure blank;
    fixed.reset();
    assert(!AuditFixedGuestDependencyClosure(fixed,blank,why));
    assert(blank.nodes.empty());
    std::puts("KERNIX_G2C_FULL_PT_INTERP_TRANSITIVE_NEEDED_FROM_SNAPSHOT_PASS_NOT_GLIBC_OR_DEVICE");
    return 0;
}
