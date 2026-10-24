/*
 * v2.9.7: host regression for Wine child-loader reexec path trust.
 *
 * Called with a path and argv that must be passed unmodified to
 * execv(). If native preload routes the trusted Wine loader to the
 * signed probe, process exits with that probe's specific return code.
 * If the path is untrusted/nonexistent, execv returns ENOENT and this
 * harness prints the error rather than escaping the test process.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc != 2) return 90;
    char *const args[]={(char *)argv[1],NULL};
    execv(argv[1],args);
    printf("RM11_V297_EXEC_UNHANDLED_ERRNO=%d\n",errno);
    return errno==ENOENT ? 67 : 68;
}
