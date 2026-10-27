package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Read-only, app-UID-only Linux process census.
 *
 * The Java Process of Wine can be a stdout-forwarding launcher in pipe_read.
 * A quiet Java Process PID does NOT prove its Win64 PE child is blocked.
 * Determine whether native Wine launcher children exist and actually receive
 * CPU ticks, without scanning other apps' cmdlines or copying user paths.
 * The kernel may hide /proc entries; UNAVAILABLE is an expected outcome.
 */
public final class WineNativeProcessCensusV488 {
    private static final int MAX_PIDS=8192;
    private static final int MAX_TRACKED=256;
    private final Map<Long,Long> lastWineTicks=new HashMap<>();
    private int samples;
    private String last="RM11_V488_APP_UID_CENSUS=NOT_SAMPLED\n";

    private WineNativeProcessCensusV488(){}
    public static WineNativeProcessCensusV488 create(){return new WineNativeProcessCensusV488();}

    static int realUid(String status){
        if(status==null)return -1;
        for(String line:status.split("\n")){
            if(line.startsWith("Uid:")){
                String[] parts=line.substring(4).trim().split("\\s+");
                if(parts.length==0)return -1;
                try{return Integer.parseInt(parts[0]);}
                catch(NumberFormatException bad){return -1;}
            }
        }
        return -1;
    }
    static String role(String command){
        if(command==null)return "UNKNOWN";
        if(command.contains("libwineserverrm11.so"))return "SERVER";
        if(command.contains("libwineprobe.so"))return "WINE_LOADER";
        return "OTHER_SAME_UID";
    }
    static String boundedRead(Path path,int limit)throws IOException{
        if(Files.isSymbolicLink(path))throw new IOException("PROC_SYMLINK");
        // Proc pseudo-file sizes often report 0. Limit actual read bytes.
        try(java.io.InputStream in=Files.newInputStream(path)){
            byte[] block=new byte[limit+1];
            int len=0,n;
            while(len<block.length&&(n=in.read(block,len,block.length-len))>0)len+=n;
            if(len>limit)throw new IOException("PROC_READ_LIMIT");
            return new String(block,0,len,StandardCharsets.UTF_8);
        }
    }
    private static boolean numericPid(String s){
        return s!=null&&s.matches("[0-9]{1,9}");
    }

    public synchronized String sample(int ownUid,long elapsedMs){
        samples++;
        int scanned=0,owned=0,loaders=0,servers=0,other=0,denied=0,parsed=0;
        int loaderRunning=0,loaderSleeping=0;
        long delta=0,loadedTicks=0;
        boolean cpuBaseline=false,limitHit=false,opened=false;
        Map<Long,Long> current=new HashMap<>();
        try(DirectoryStream<Path> items=Files.newDirectoryStream(Path.of("/proc"))){
            opened=true;
            for(Path p:items){
                if(!numericPid(p.getFileName().toString()))continue;
                if(++scanned>MAX_PIDS){limitHit=true;break;}
                try{
                    // IMPORTANT: never inspect cmdline or stat of a process
                    // unless the kernel reports this app's exact real UID.
                    String status=boundedRead(p.resolve("status"),8192);
                    if(realUid(status)!=ownUid)continue;
                    owned++;
                    String cmd=boundedRead(p.resolve("cmdline"),2048);
                    String role=role(cmd);
                    if("WINE_LOADER".equals(role)){
                        loaders++;
                        GameProcessActivityEvidenceV487.Stat stat=
                                GameProcessActivityEvidenceV487.parseStat(
                                        boundedRead(p.resolve("stat"),8192));
                        parsed++;
                        if(stat.state=='R')loaderRunning++;
                        if(stat.state=='S'||stat.state=='D')loaderSleeping++;
                        long ticks=stat.cpuTicks();
                        loadedTicks+=ticks;
                        long pid=Long.parseLong(p.getFileName().toString());
                        if(current.size()<MAX_TRACKED)current.put(pid,ticks);
                        Long before=lastWineTicks.get(pid);
                        if(before!=null&&ticks>=before){
                            cpuBaseline=true;delta+=ticks-before;
                        }
                    }else if("SERVER".equals(role))servers++;
                    else other++;
                }catch(IOException|SecurityException|IllegalArgumentException deniedEntry){
                    denied++;
                }
            }
        }catch(IOException|SecurityException unavailable){
            last="RM11_V488_APP_UID_CENSUS=UNAVAILABLE_"
                    +unavailable.getClass().getSimpleName()+"\n"
                    +"RM11_V488_OTHER_APP_PROCESSES_EXCLUDED=true\n";
            return last;
        }
        lastWineTicks.clear();
        lastWineTicks.putAll(current);
        StringBuilder s=new StringBuilder(650);
        s.append("RM11_V488_APP_UID_CENSUS=").append(opened?"OK":"UNAVAILABLE").append('\n')
         .append("RM11_V488_SAMPLE=").append(samples).append('\n')
         .append("RM11_V488_ELAPSED_MS=").append(elapsedMs).append('\n')
         .append("RM11_V488_PROC_ENTRIES_EXAMINED=").append(scanned).append('\n')
         .append("RM11_V488_PROC_SCAN_CAPPED=").append(limitHit).append('\n')
         .append("RM11_V488_APP_OWNED_PROCESS_COUNT=").append(owned).append('\n')
         .append("RM11_V488_WINE_LOADER_PROCESS_COUNT=").append(loaders).append('\n')
         .append("RM11_V488_WINESERVER_PROCESS_COUNT=").append(servers).append('\n')
         .append("RM11_V488_OTHER_SAME_UID_PROCESSES=").append(other).append('\n')
         .append("RM11_V488_WINE_LOADER_STAT_READ_OK=").append(parsed).append('\n')
         .append("RM11_V488_WINE_LOADERS_RUNNING=").append(loaderRunning).append('\n')
         .append("RM11_V488_WINE_LOADERS_SLEEPING=").append(loaderSleeping).append('\n')
         .append("RM11_V488_WINE_LOADERS_CUMULATIVE_CPU_TICKS=").append(loadedTicks).append('\n')
         .append("RM11_V488_WINE_LOADER_CPU_DELTA=");
        if(samples==1||!cpuBaseline)s.append("NO_MATCHING_PRIOR_NATIVE_PROCESS");
        else s.append(delta);
        s.append('\n')
         .append("RM11_V488_PERMISSION_OR_RACE_DENIALS=").append(denied).append('\n')
         .append("RM11_V488_OTHER_APP_PROCESSES_EXCLUDED=true\n")
         .append("RM11_V488_PE_PROGRESS=UNVERIFIED\n");
        return last=s.toString();
    }
    public synchronized String last(){return last;}
}
