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
        final String module;
        Entry(long a,long b,long offset,String basename){
            first=a;last=b;fileOffset=offset;module=basename;
        }
    }
    private final ArrayList<Entry> regions=new ArrayList<>();
    private String lastState="NOT_SAMPLED";
    private int attempts;
    private int success;

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
            regions.add(new Entry(start,end,off,shortModule(m.group(5))));
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
}
