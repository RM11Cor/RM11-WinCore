package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * v489: Best-effort, read-only app UID native process activity.
 *
 * v488 scanned 97 same-UID processes but classified 0 as Wine clients
 * by matching only argv strings. The v486 Wine trace independently proved
 * that the selected CarX PE loaded. Identify Wine by argv0, comm or exe
 * symlink basename; report aggregate per-app CPU deltas even if the Wine
 * client keeps an unusual process title. Never export PIDs, paths, argv,
 * process titles, thread memory or data from another UID.
 */
public final class WineNativeProcessActivityV489 {
    private static final int MAX_PROCESSES=512;
    private static final int MAX_STATUS_BYTES=8192;
    private final Map<Long,Long> priorTicks=new HashMap<>();
    private final Map<Long,Long> priorWineTicks=new HashMap<>();
    private int samples;
    private String last="RM11_V489_PROCESS_ACTIVITY=NOT_SAMPLED\n";

    private WineNativeProcessActivityV489(){}
    public static WineNativeProcessActivityV489 create(){
        return new WineNativeProcessActivityV489();
    }
    static String category(String argv,String comm,String elf){
        String a=argv==null?"":argv;
        String c=comm==null?"":comm;
        String e=elf==null?"":elf;
        if(a.contains("libwineserverrm11.so")||c.contains("wineserver")||
                e.contains("libwineserverrm11.so"))
            return "WINE_SERVER";
        if(a.contains("libwineprobe.so")||c.contains("libwineprobe")||
                e.contains("libwineprobe.so")||c.equals("wine64")||
                c.equals("wine")||e.endsWith("/wine64")||e.endsWith("/wine"))
            return "WINE_CLIENT";
        return "UNKNOWN_APP_PROCESS";
    }
    static boolean numericPid(String s){
        return s!=null&&s.matches("[0-9]{1,9}");
    }
    private static String readLimited(Path path,int max)throws IOException{
        if(Files.isSymbolicLink(path))throw new IOException("SYMLINK");
        try(java.io.InputStream in=Files.newInputStream(path)){
            byte[] data=new byte[max+1];
            int n,len=0;
            while(len<data.length&&(n=in.read(data,len,data.length-len))>0)
                len+=n;
            if(len>max)throw new IOException("TOO_LONG");
            return new String(data,0,len,StandardCharsets.UTF_8);
        }
    }
    public synchronized String sample(int ownUid,long elapsedMs){
        samples++;
        int visited=0,own=0,statOk=0,statDenied=0,uidDenied=0;
        int wineClients=0,wineServers=0,unclassified=0;
        int running=0,sleeping=0,otherState=0;
        int exeSymlinkReadable=0,activityCompared=0,cpuAdvanced=0;
        int wineActivityCompared=0,wineCpuAdvanced=0;
        long aggregateTickDelta=0,wineTickDelta=0;
        boolean first=samples==1,capped=false;
        Map<Long,Long> now=new HashMap<>();
        Map<Long,Long> wineNow=new HashMap<>();
        try(DirectoryStream<Path> proc=Files.newDirectoryStream(Path.of("/proc"))){
            for(Path p:proc){
                if(!numericPid(p.getFileName().toString()))continue;
                if(++visited>MAX_PROCESSES){capped=true;break;}
                String status;
                try{status=readLimited(p.resolve("status"),MAX_STATUS_BYTES);}
                catch(IOException|SecurityException access){uidDenied++;continue;}
                if(WineNativeProcessCensusV488.realUid(status)!=ownUid)continue;
                own++;
                long pid;
                try{pid=Long.parseLong(p.getFileName().toString());}
                catch(NumberFormatException race){continue;}
                String argv="",comm="",exe="";
                try{argv=readLimited(p.resolve("cmdline"),1536);}
                catch(IOException|SecurityException inaccessible){ }
                try{comm=readLimited(p.resolve("comm"),128).trim();}
                catch(IOException|SecurityException inaccessible){ }
                try{
                    // Read symbolic target of this app's own native executable.
                    // Only category is exported; the target is never retained.
                    exe=Files.readSymbolicLink(p.resolve("exe")).toString();
                    exeSymlinkReadable++;
                }catch(IOException|SecurityException inaccessible){ }
                String group=category(argv,comm,exe);
                if("WINE_CLIENT".equals(group))wineClients++;
                else if("WINE_SERVER".equals(group))wineServers++;
                else unclassified++;
                try{
                    GameProcessActivityEvidenceV487.Stat stat=
                            GameProcessActivityEvidenceV487.parseStat(
                                    readLimited(p.resolve("stat"),8192));
                    statOk++;
                    if(stat.state=='R')running++;
                    else if(stat.state=='S'||stat.state=='D')sleeping++;
                    else otherState++;
                    long ticks=stat.cpuTicks();
                    now.put(pid,ticks);
                    Long prior=priorTicks.get(pid);
                    if(prior!=null&&ticks>=prior){
                        activityCompared++;
                        long diff=ticks-prior;
                        aggregateTickDelta+=diff;
                        if(diff>0)cpuAdvanced++;
                    }
                    if("WINE_CLIENT".equals(group)){
                        wineNow.put(pid,ticks);
                        Long old=priorWineTicks.get(pid);
                        if(old!=null&&ticks>=old){
                            wineActivityCompared++;
                            long diff=ticks-old;
                            wineTickDelta+=diff;
                            if(diff>0)wineCpuAdvanced++;
                        }
                    }
                }catch(IOException|SecurityException|IllegalArgumentException denied){
                    statDenied++;
                }
            }
        }catch(IOException|SecurityException scanDenied){
            last="RM11_V489_PROCESS_ACTIVITY=UNAVAILABLE_"
                    +scanDenied.getClass().getSimpleName()+"\n"
                    +"RM11_V489_FOREIGN_UID_DATA_INCLUDED=false\n";
            return last;
        }
        priorTicks.clear();
        priorTicks.putAll(now);
        priorWineTicks.clear();
        priorWineTicks.putAll(wineNow);
        StringBuilder b=new StringBuilder(950);
        b.append("RM11_V489_PROCESS_ACTIVITY=OK\n")
         .append("RM11_V489_SAMPLE=").append(samples).append('\n')
         .append("RM11_V489_ELAPSED_MS=").append(elapsedMs).append('\n')
         .append("RM11_V489_PROC_PID_ENTRIES_EXAMINED=").append(visited).append('\n')
         .append("RM11_V489_PROC_SCAN_CAPPED=").append(capped).append('\n')
         .append("RM11_V489_APP_UID_PROCESS_COUNT=").append(own).append('\n')
         .append("RM11_V489_STAT_READ_OK=").append(statOk).append('\n')
         .append("RM11_V489_STAT_DENIED=").append(statDenied).append('\n')
         .append("RM11_V489_UID_READ_DENIED=").append(uidDenied).append('\n')
         .append("RM11_V489_EXE_LINK_READ_OK=").append(exeSymlinkReadable).append('\n')
         .append("RM11_V489_WINE_CLIENT_IDENTIFIED=").append(wineClients).append('\n')
         .append("RM11_V489_WINE_SERVER_IDENTIFIED=").append(wineServers).append('\n')
         .append("RM11_V489_APP_UNCLASSIFIED_PROCESSES=").append(unclassified).append('\n')
         .append("RM11_V489_PROCESS_STATE_RUNNING=").append(running).append('\n')
         .append("RM11_V489_PROCESS_STATE_SLEEPING=").append(sleeping).append('\n')
         .append("RM11_V489_PROCESS_STATE_OTHER=").append(otherState).append('\n')
         .append("RM11_V489_AGGREGATE_CPU_COMPARABLE_PROCESSES=").append(activityCompared).append('\n')
         .append("RM11_V489_AGGREGATE_CPU_ADVANCING_PROCESSES=").append(cpuAdvanced).append('\n')
         .append("RM11_V489_AGGREGATE_CPU_TICKS_DELTA=");
        if(first||activityCompared==0)b.append("NO_COMPARABLE_PRIOR_SAMPLE");
        else b.append(aggregateTickDelta);
        b.append('\n')
         .append("RM11_V489_IDENTIFIED_WINE_CPU_COMPARABLE=").append(wineActivityCompared).append('\n')
         .append("RM11_V489_IDENTIFIED_WINE_CPU_ADVANCING=").append(wineCpuAdvanced).append('\n')
         .append("RM11_V489_IDENTIFIED_WINE_CPU_DELTA=");
        if(first||wineActivityCompared==0)b.append("NO_COMPARABLE_PRIOR_SAMPLE");
        else b.append(wineTickDelta);
        b.append("\nRM11_V489_FOREIGN_UID_DATA_INCLUDED=false\n")
         .append("RM11_V489_GAME_PE_THREAD_STATE=UNVERIFIED\n");
        return last=b.toString();
    }
    public synchronized String last(){return last;}
}
