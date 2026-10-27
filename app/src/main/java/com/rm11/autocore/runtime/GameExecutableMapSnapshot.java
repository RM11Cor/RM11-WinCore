package com.rm11.autocore.runtime;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Best-effort, read-only map lookup for a process started by this app.
 * Android may deny /proc/<pid>/maps access: DENIED is an expected outcome.
 * No full storage paths are exported, only sanitized image basenames.
 */
public final class GameExecutableMapSnapshot {
    private static final int MAX_ENTRIES=1500;
    private static final Pattern MAP=Pattern.compile(
        "^([0-9a-fA-F]+)-([0-9a-fA-F]+)\\s+([rwxps-]{4})\\s+([0-9a-fA-F]+)\\s+\\S+\\s+\\d+\\s*(.*)$");
    private static final class Entry {
        final long first,last,fileOffset;
        final String module,permissions;
        Entry(long a,long b,long offset,String basename,String flags){
            first=a;last=b;fileOffset=offset;module=basename;permissions=flags;
        }
    }
    private final ArrayList<Entry> regions=new ArrayList<>();
    private String lastState="NOT_SAMPLED";
    private int attempts;
    private int success;

    /**
     * Android's compile SDK may not expose java.lang.Process.pid().
     * Query only public runtime accessors when present; never read private
     * fields or assume the app PID is the Wine child PID.
     */
    public static long findLaunchedProcessPid(Process child) {
        if(child==null)return -1;
        for(String method:new String[]{"pid","getPid"}) {
            try {
                Object value=child.getClass().getMethod(method).invoke(child);
                if(value instanceof Number) {
                    long n=((Number)value).longValue();
                    if(n>0)return n;
                }
            }catch(ReflectiveOperationException|SecurityException ignored) {
                // Hidden or inaccessible on this Android runtime.
            }
        }
        try {
            java.util.regex.Matcher m=Pattern.compile("(?:^|[^A-Za-z])pid[=: ]+([0-9]{1,10})",
                    Pattern.CASE_INSENSITIVE).matcher(child.toString());
            if(m.find()){
                long n=Long.parseLong(m.group(1));
                if(n>0)return n;
            }
        }catch(RuntimeException ignored) {
            // Some libcore Process implementations have opaque toString().
        }
        return -1;
    }

    private static String shortModule(String raw) {
        if(raw==null||raw.isEmpty())return "ANONYMOUS_EXECUTABLE";
        if(raw.startsWith("["))return "ANONYMOUS_OR_SPECIAL_MAPPING";
        String base=raw.substring(raw.lastIndexOf('/')+1);
        if(base.length()>90)base=base.substring(0,90);
        return base.replaceAll("[^A-Za-z0-9_.+@-]","_");
    }
    // Package-visible for deterministic unit tests without procfs privileges.
    synchronized void acceptLine(String text) {
        Matcher m=MAP.matcher(text);
        if(!m.matches()||m.group(3).charAt(2)!='x'
                ||regions.size()>=MAX_ENTRIES)return;
        try {
            long start=Long.parseUnsignedLong(m.group(1),16);
            long end=Long.parseUnsignedLong(m.group(2),16);
            long off=Long.parseUnsignedLong(m.group(4),16);
            if(Long.compareUnsigned(start,end)>=0)return;
            for(Entry e:regions)
                if(e.first==start && e.last==end)return;
            regions.add(new Entry(start,end,off,shortModule(m.group(5)),m.group(3)));
        }catch(NumberFormatException ignored){ }
    }
    public synchronized void sample(long appLaunchedProcessId) {
        attempts++;
        if(appLaunchedProcessId<=0) {lastState="INVALID_PID";return;}
        try(BufferedReader reader=Files.newBufferedReader(
                Path.of("/proc",Long.toString(appLaunchedProcessId),"maps"))) {
            String line;
            int read=0;
            while((line=reader.readLine())!=null && read++<3000) {
                acceptLine(line);
                if(regions.size()>=MAX_ENTRIES)break;
            }
            success++;
            lastState="OK";
        }catch(IOException|SecurityException denied){
            lastState="UNAVAILABLE_"+denied.getClass().getSimpleName();
        }
    }
    public synchronized String resolve(String pcHex) {
        StringBuilder out=new StringBuilder("RM11_V463_GAME_NATIVE_MAP\n");
        out.append("RM11_V463_MAP_SAMPLES_ATTEMPTED=").append(attempts).append('\n')
           .append("RM11_V463_MAP_SAMPLES_SUCCEEDED=").append(success).append('\n')
           .append("RM11_V463_MAP_LAST_STATUS=").append(lastState).append('\n')
           .append("RM11_V463_MAP_EXEC_RANGES=").append(regions.size()).append('\n');
        if(pcHex==null||!pcHex.matches("[0-9a-fA-F]{5,16}"))
            return out.append("RM11_V463_ASSERT_RIP_RESOLUTION=NO_PC\n").toString();
        try {
            long pc=Long.parseUnsignedLong(pcHex,16);
            for(Entry e:regions) {
                if(Long.compareUnsigned(pc,e.first)>=0
                        &&Long.compareUnsigned(pc,e.last)<0) {
                    out.append("RM11_V463_ASSERT_RIP_RESOLUTION=MAPPED\n")
                       .append("RM11_V463_ASSERT_RIP_IMAGE=").append(e.module).append('\n')
                       .append("RM11_V463_ASSERT_RIP_MODULE_OFFSET=0x")
                       .append(Long.toHexString(pc-e.first+e.fileOffset)).append('\n');
                    return out.toString();
                }
            }
        }catch(NumberFormatException bad){
            return out.append("RM11_V463_ASSERT_RIP_RESOLUTION=INVALID_PC\n").toString();
        }
        return out.append("RM11_V463_ASSERT_RIP_RESOLUTION=UNMAPPED_OR_NOT_SAMPLED\n").toString();
    }
    /**
     * Bounded v469 memory-map neighborhood around the actual native fault PC.
     * Executable maps only; no process-memory reads, no full paths and no
     * assumptions that a nameless map necessarily belongs to a JIT.
     * Neighbors show proximity only, NOT module ownership.
     */
    public synchronized String nearbyExecutableRegions(String pcHex) {
        StringBuilder out=new StringBuilder("RM11_V469_EXEC_REGION_NEIGHBORHOOD\n");
        if(pcHex==null||!pcHex.matches("[0-9a-fA-F]{5,16}"))
            return out.append("RM11_V469_PC_STATUS=UNAVAILABLE\n").toString();
        try {
            long pc=Long.parseUnsignedLong(pcHex,16);
            Entry match=null,lower=null,upper=null;
            for(Entry r:regions) {
                if(Long.compareUnsigned(pc,r.first)>=0
                    &&Long.compareUnsigned(pc,r.last)<0)match=r;
                if(Long.compareUnsigned(r.last,pc)<=0
                    &&(lower==null||Long.compareUnsigned(r.last,lower.last)>0))lower=r;
                if(Long.compareUnsigned(r.first,pc)>0
                    &&(upper==null||Long.compareUnsigned(r.first,upper.first)<0))upper=r;
            }
            out.append("RM11_V469_PC=0x").append(Long.toHexString(pc)).append('\n')
               .append("RM11_V469_EXEC_RANGES=").append(regions.size()).append('\n');
            if(match==null)return out.append("RM11_V469_PC_STATUS=NOT_IN_SAMPLED_EXEC_MAP\n")
                    .toString();
            out.append("RM11_V469_PC_STATUS=MAPPED\n");
            appendRegion(out,"MATCH",match);
            out.append("RM11_V469_MATCH_OFFSET_IN_REGION=0x")
               .append(Long.toHexString(pc-match.first)).append('\n');
            out.append("RM11_V469_MATCH_ANONYMOUS=")
               .append("ANONYMOUS_EXECUTABLE".equals(match.module)).append('\n');
            if(lower!=null) {
                appendRegion(out,"PREVIOUS_EXEC_ONLY",lower);
                out.append("RM11_V469_PREVIOUS_EXEC_GAP_BYTES=")
                   .append(Long.toUnsignedString(pc-lower.last)).append('\n');
            }
            if(upper!=null) {
                appendRegion(out,"NEXT_EXEC_ONLY",upper);
                out.append("RM11_V469_NEXT_EXEC_GAP_BYTES=")
                   .append(Long.toUnsignedString(upper.first-pc)).append('\n');
            }
            return out.toString();
        }catch(NumberFormatException bad){
            return out.append("RM11_V469_PC_STATUS=INVALID_PC\n").toString();
        }
    }
    private static void appendRegion(StringBuilder out,String role,Entry e) {
        out.append("RM11_V469_").append(role).append("_MODULE=").append(e.module).append('\n')
           .append("RM11_V469_").append(role).append("_PERMISSIONS=").append(e.permissions).append('\n')
           .append("RM11_V469_").append(role).append("_START=0x")
           .append(Long.toHexString(e.first)).append('\n')
           .append("RM11_V469_").append(role).append("_END=0x")
           .append(Long.toHexString(e.last)).append('\n')
           .append("RM11_V469_").append(role).append("_FILE_OFFSET=0x")
           .append(Long.toHexString(e.fileOffset)).append('\n');
    }

}
