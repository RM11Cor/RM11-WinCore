/*
 * RM11 Engine vNext: Linux child-process/session reaper prototype.
 *
 * This is a new *native supervisor process*, NOT injected into Wine or
 * Android's Java Process implementation. On Linux PR_SET_CHILD_SUBREAPER
 * makes orphaned descendants its children; only then may waitpid() reap them.
 * This does NOT magically reap a zombie still owned by a living Wine parent.
 *
 * Host CI tests this under Linux. It is NOT yet an Android signed ELF, an
 * integrated Wine launcher, or evidence of Android game rendering.
 *
 * Native ELF path trust and SHA256 must be enforced by the signed APK caller.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define POLL_MS 20
#define TERM_GRACE_MS 900
#define HARD_LIMIT_MS 5000

static volatile sig_atomic_t interrupted=0;
static void stopped(int signal_number) {
    (void)signal_number;
    interrupted=1;
}
static long ms_now(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)<0)return 0;
    return (long)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void sleep_poll(void){
    struct timespec t={0,POLL_MS*1000000L};
    nanosleep(&t,NULL);
}
static bool prefix_path(const char *candidate,const char *root){
    size_t n=strlen(root);
    return n>1 && !strncmp(candidate,root,n) &&
        candidate[n]=='/' && candidate[n+1]!='\0';
}
static int accepted_binary(const char *path){
    const char *root=getenv("RM11_ENGINE_APK_LIB_DIR");
    if(!path||!root||path[0]!='/'||root[0]!='/')return 0;
    char canonical_root[PATH_MAX], canonical_binary[PATH_MAX];
    if(!realpath(root,canonical_root)||!realpath(path,canonical_binary))
        return 0;
    const char *last=strrchr(canonical_binary,'/');
    if(!last || !prefix_path(canonical_binary,canonical_root))
        return 0;
    /* Native supervisor is restricted to top-level APK signed launchers.
     * No running arbitrary user EXEs or nested writable ImageFs binaries.
     */
    if(strcmp(last+1,"libwineprobe.so") &&
       strcmp(last+1,"libwineserverrm11.so"))return 0;
    size_t rlen=strlen(canonical_root);
    const char *relative=canonical_binary+rlen+1;
    // One direct executable child of the signed APK library directory.
    // Prevent accidental execution of nested ImageFs or user files.
    return !strchr(relative,'/');
}
static void signal_group(pid_t pgid,int sig){
    /* Only this supervisor-created process group can receive signals. */
    if(pgid>1)kill(-pgid,sig);
}
static void install_signal_handlers(void){
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler=stopped;
    sigaction(SIGTERM,&sa,NULL);
    sigaction(SIGINT,&sa,NULL);
}

int main(int argc,char **argv){
    if(argc<2 || !accepted_binary(argv[1])){
        fprintf(stderr,"RM11_ENGINE_NATIVE_ENTRYPOINT_NOT_APPROVED\n");
        return 64;
    }
    if(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)<0){
        fprintf(stderr,"RM11_ENGINE_SUBREAPER_UNAVAILABLE\n");
        return 65;
    }
    install_signal_handlers();
    pid_t child=fork();
    if(child<0){
        fprintf(stderr,"RM11_ENGINE_GUEST_FORK_FAILED\n");
        return 66;
    }
    if(child==0){
        if(setpgid(0,0)<0)_exit(126);
        execv(argv[1],&argv[1]);
        _exit(127);
    }
    /* Best effort to close fork/exec race; child also sets its group. */
    if(setpgid(child,child)<0 && errno!=EACCES && errno!=ESRCH){
        signal_group(child,SIGKILL);
        waitpid(child,NULL,0);
        return 67;
    }

    int root_status=0,root_seen=0,reaped=0;
    bool sent_term=false,sent_kill=false;
    long term_at=0,hard_at=0;
    for(;;){
        int status;
        pid_t pid;
        while((pid=waitpid(-1,&status,WNOHANG))>0){
            reaped++;
            if(pid==child){
                root_seen=1;
                root_status=status;
            }
        }
        if(pid==-1 && errno!=ECHILD && errno!=EINTR){
            fprintf(stderr,"RM11_ENGINE_REAPER_WAITPID_ERROR\n");
            break;
        }
        long now=ms_now();
        // The loader may exit after creating the real Windows game child.
        // Root exit alone is not permission to kill that child. Only an
        // explicit session-stop signal may terminate the owned group.
        if(!sent_term && interrupted){
            signal_group(child,SIGTERM);
            sent_term=true;
            term_at=now;
            hard_at=now+HARD_LIMIT_MS;
        }
        if(sent_term && !sent_kill && now-term_at>=TERM_GRACE_MS){
            signal_group(child,SIGKILL);
            sent_kill=true;
        }
        if(root_seen && pid==-1 && errno==ECHILD)break;
        if(sent_term && now>=hard_at){
            signal_group(child,SIGKILL);
            fprintf(stderr,"RM11_ENGINE_REAPER_HARD_DEADLINE\n");
            break;
        }
        if(!sent_term && pid==-1 && errno==ECHILD) {
            /* Parent unexpectedly has no children; never wait forever. */
            break;
        }
        sleep_poll();
    }

    fprintf(stderr,"RM11_ENGINE_NATIVE_REAP_COMPLETED reaped=%d root=%d\n",
            reaped,root_seen);
    if(interrupted)return 128+SIGTERM;
    if(!root_seen)return 68;
    if(WIFEXITED(root_status))return WEXITSTATUS(root_status);
    if(WIFSIGNALED(root_status))return 128+WTERMSIG(root_status);
    return 69;
}
