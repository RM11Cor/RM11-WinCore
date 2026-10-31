package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;

/**
 * Read-only, scoped native Linux process liveness and scheduling samples
 * for the specific app-launched Wine process. A process staying alive is
 * NOT evidence that the PE made progress. No arbitrary /proc iteration,
 * other app information, executable paths or network activity.
 *
 * /proc access may be denied by Android SELinux. Every failure is captured
 * as UNAVAILABLE, not guessed. Sampling is intentionally sparse.
 */
public final class GameProcessActivityEvidenceV487 {
    public static final class Stat {
        public final char state;
        public final long userTicks,systemTicks;
        public final int threads;
        Stat(char s,long ut,long st,int nt){
            state=s;userTicks=ut;systemTicks=st;threads=nt;
        }
        public long cpuTicks(){return userTicks+systemTicks;}
    }
    private long previousTicks=-1,previousElapsed=-1;
    private long previousThreadGroupTicks=-1;
    private int samples;
    private String lastReport="RM11_V487_PROCFS=NOT_SAMPLED\n";
    private GameProcessActivityEvidenceV487(){}

    public static GameProcessActivityEvidenceV487 create(){
        return new GameProcessActivityEvidenceV487();
    }

    /** Linux proc stat fields start at #3 immediately after ") ".
     * Supports comm with whitespace, parentheses and digits. */
    static Stat parseStat(String raw){
        if(raw==null)throw new IllegalArgumentException("EMPTY_STAT");
        int closing=raw.lastIndexOf(") ");
        if(closing<2)throw new IllegalArgumentException("STAT_COMM_CLOSURE_MISSING");
        String[] tail=raw.substring(closing+2).trim().split("\\s+");
        if(tail.length<18)throw new IllegalArgumentException("STAT_FIELDS_SHORT");
        char state=tail[0].charAt(0); // Linux field #3
        long ut=Long.parseLong(tail[11]); // Linux field #14
        long st=Long.parseLong(tail[12]); // Linux field #15
        int n=Integer.parseInt(tail[17]); // Linux field #20
        if(ut<0||st<0||n<0)throw new IllegalArgumentException("STAT_NEGATIVE");
        return new Stat(state,ut,st,n);
    }

    /** Linux can keep a thread-group leader in Z while non-leader tasks
     * survive. Do not claim that Java waitFor() must already have completed.
     * Sampling unknown/denied task status is not proof of a live game. */
    static String classifyThreadGroup(char leaderState,int reportedThreads,
            int observedNonLeaderLiveTasks) {
        if(leaderState!='Z')return "LEADER_NOT_Z";
        if(observedNonLeaderLiveTasks>0)
            return "LEADER_Z_WITH_NONLEADER_LIVE_TASKS_CONFIRMED";
        if(reportedThreads>1)
            return "LEADER_Z_MULTITHREAD_POSSIBLE_TASK_STATES_UNVERIFIED";
        return "LEADER_Z_NO_LIVE_NONLEADER_TASK_PROOF";
    }

    private static String safeRead(Path path,int maxBytes) throws IOException {
        long size=Files.size(path);
        if(size>maxBytes)throw new IOException("PROC_ENTRY_TOO_LARGE");
        byte[] data=Files.readAllBytes(path);
        if(data.length>maxBytes)throw new IOException("PROC_ENTRY_TOO_LARGE");
        return new String(data,StandardCharsets.UTF_8);
    }

    static int childCount(String children) {
        if(children==null||children.trim().isEmpty())return 0;
        int count=0;
        for(String child:children.trim().split("\\s+")){
            if(child.matches("[0-9]{1,9}"))count++;
        }
        return count;
    }

    public synchronized String sample(long launchedPid,long elapsedMs,
            boolean processAlive){
        samples++;
        StringBuilder output=new StringBuilder(900);
        output.append("RM11_V487_GAME_PROCESS_ACTIVATION_AUDIT\n")
              .append("RM11_V487_SAMPLE=").append(samples).append('\n')
              .append("RM11_V487_ELAPSED_MS=").append(elapsedMs).append('\n')
              .append("RM11_V487_LAUNCHER_PROCESS_ALIVE=").append(processAlive).append('\n');
        if(launchedPid<=0){
            return lastReport=output.append("RM11_V487_PROCFS=PID_NOT_OBSERVABLE\n")
                    .append("RM11_V487_SELECTED_PE_PROGRESS=UNVERIFIED\n").toString();
        }
        Path dir=Path.of("/proc",Long.toString(launchedPid));
        char leaderState='?';
        int reportedThreads=-1;
        try {
            Stat stat=parseStat(safeRead(dir.resolve("stat"),8192));
            long ticks=stat.cpuTicks();
            leaderState=stat.state;
            reportedThreads=stat.threads;
            output.append("RM11_V487_PROCFS=PROCESS_STAT_READ_OK\n")
                  .append("RM11_V487_NATIVE_PROCESS_STATE=").append(stat.state).append('\n')
                  .append("RM11_V49075_NATIVE_PROCESS_ZOMBIE=").append(stat.state=='Z').append('\n')
                  .append("RM11_V487_NATIVE_THREADS=").append(stat.threads).append('\n')
                  .append("RM11_V487_NATIVE_CPU_TICKS_TOTAL=").append(ticks).append('\n');
            if(previousTicks>=0) {
                long delta=ticks-previousTicks;
                output.append("RM11_V487_CPU_TICKS_CHANGE=").append(delta).append('\n')
                      .append("RM11_V487_SAMPLE_INTERVAL_MS=")
                      .append(elapsedMs-previousElapsed).append('\n')
                      .append("RM11_V487_CPU_STAGNANT_SINCE_PRIOR_SAMPLE=")
                      .append(delta==0).append('\n');
            } else output.append("RM11_V487_CPU_TICKS_CHANGE=INITIAL_SAMPLE\n");
            previousTicks=ticks;
            previousElapsed=elapsedMs;
        }catch(Exception unavailable){
            output.append("RM11_V487_PROCFS=UNAVAILABLE_")
                  .append(unavailable.getClass().getSimpleName()).append('\n');
        }
        // v49088: bounded, own-launched-PID-only /proc/<pid>/task sampling.
        // No TIDs, argv, memory, stacks or private paths are exported.
        int enumerated=0,readable=0,nonLeaderLive=0,running=0,sleeping=0,
                zombie=0,other=0;
        long totalThreadTicks=0;
        String taskState="TASK_SCAN_UNAVAILABLE";
        try(DirectoryStream<Path> taskEntries=
                Files.newDirectoryStream(dir.resolve("task"))) {
            for(Path task:taskEntries) {
                if(enumerated>=64)break;
                String name=task.getFileName().toString();
                if(!name.matches("[0-9]{1,10}"))continue;
                enumerated++;
                try{
                    Stat thread=parseStat(safeRead(task.resolve("stat"),8192));
                    readable++;
                    totalThreadTicks+=thread.cpuTicks();
                    if(thread.state=='R')running++;
                    else if(thread.state=='S'||thread.state=='D'||thread.state=='I')
                        sleeping++;
                    else if(thread.state=='Z'||thread.state=='X')zombie++;
                    else other++;
                    if(!name.equals(Long.toString(launchedPid))
                            &&thread.state!='Z'&&thread.state!='X')
                        nonLeaderLive++;
                }catch(Exception taskUnavailable) {
                    // Do not infer other thread states from a denied read.
                }
            }
            taskState=readable==enumerated?"OK":
                    "PARTIAL_READABLE_"+readable+"_OF_"+enumerated;
        }catch(Exception denied){
            taskState="UNAVAILABLE_"+denied.getClass().getSimpleName();
        }
        output.append("RM11_V49088_THREAD_SCAN=").append(taskState).append('\n')
              .append("RM11_V49088_TASK_ENTRIES=").append(enumerated).append('\n')
              .append("RM11_V49088_TASK_STAT_READ_OK=").append(readable).append('\n')
              .append("RM11_V49088_NONLEADER_LIVE_TASKS=").append(nonLeaderLive).append('\n')
              .append("RM11_V49088_TASK_STATES_R=").append(running).append('\n')
              .append("RM11_V49088_TASK_STATES_SLEEPING=").append(sleeping).append('\n')
              .append("RM11_V49088_TASK_STATES_Z_OR_X=").append(zombie).append('\n')
              .append("RM11_V49088_TASK_STATES_OTHER=").append(other).append('\n')
              .append("RM11_V49088_LEADER_GROUP_DIAGNOSIS=")
              .append(classifyThreadGroup(leaderState,reportedThreads,nonLeaderLive))
              .append('\n');
        if(readable>0){
            output.append("RM11_V49088_TASK_CPU_TICKS_SUM=")
                  .append(totalThreadTicks).append('\n');
            output.append("RM11_V49088_TASK_CPU_TICKS_DELTA=")
                  .append(previousThreadGroupTicks<0?"INITIAL_SAMPLE":
                          Long.toString(totalThreadTicks-previousThreadGroupTicks))
                  .append('\n');
            previousThreadGroupTicks=totalThreadTicks;
        }
        try{
            // Only the already known child Linux PID; no global /proc scan.
            String wchan=safeRead(dir.resolve("wchan"),256).trim();
            output.append("RM11_V487_MAIN_THREAD_WAIT_CHANNEL=")
                  .append(wchan.matches("[A-Za-z_0-9.]{1,70}")?wchan:"UNAVAILABLE")
                  .append('\n');
        }catch(Exception unavailable){
            output.append("RM11_V487_MAIN_THREAD_WAIT_CHANNEL=UNAVAILABLE_")
                  .append(unavailable.getClass().getSimpleName()).append('\n');
        }
        try {
            // Direct child PIDs are not exposed. Report ONLY the number.
            Path children=dir.resolve("task").resolve(Long.toString(launchedPid))
                    .resolve("children");
            int count=childCount(safeRead(children,8192));
            output.append("RM11_V487_DIRECT_NATIVE_CHILD_COUNT=")
                    .append(count).append('\n');
        }catch(Exception unavailable) {
            output.append("RM11_V487_DIRECT_NATIVE_CHILD_COUNT=UNAVAILABLE_")
                    .append(unavailable.getClass().getSimpleName()).append('\n');
        }
        output.append("RM11_V487_SELECTED_PE_PROGRESS=UNVERIFIED\n")
              .append("RM11_V487_THREAD_STACKS=NOT_READ\n");
        return lastReport=output.toString();
    }
    public synchronized String last(){return lastReport;}
}
