package com.fh5.port;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * P3.5 - Static compatibility planning only.
 * "Local present" means a file with an imported DLL filename exists next
 * to ForzaHorizon5.exe, not that its imports/ABI/license are functional.
 * "Not found beside EXE" does NOT mean that a Windows runtime lacks it.
 */
public final class DllDependencyPlanner {
    private DllDependencyPlanner() { }

    public static final String LOCAL_PRESENT="FILENAME_PRESENT_BESIDE_EXE";
    public static final String NOT_LOCAL="NOT_FOUND_BESIDE_EXE";
    public static final String NOT_CHECKED="FOLDER_NOT_VERIFIED";

    public static final class Entry {
        public final String name,group,localStatus;
        Entry(String n,String g,String s){name=n;group=g;localStatus=s;}
    }
    public static final class Report {
        public final List<Entry> entries;
        public final int localCount,notLocalCount,notCheckedCount,apiSetCount;
        Report(List<Entry> entries,int local,int absent,int unchecked,int api){
            this.entries=Collections.unmodifiableList(entries);
            localCount=local;notLocalCount=absent;
            notCheckedCount=unchecked;apiSetCount=api;
        }
    }
    public static String group(String raw) {
        if(raw==null)return "OTHER_IMPORT";
        String n=raw.toLowerCase(Locale.ROOT);
        if(n.startsWith("api-ms-win-")||n.startsWith("ext-ms-win-"))
            return "WINDOWS_API_SET_CONTRACT";
        if(n.equals("d3d12.dll")||n.equals("dxgi.dll"))
            return "DX12_GRAPHICS_BRIDGE_REQUIRED";
        if(n.startsWith("vcruntime")||n.startsWith("msvcp")||
           n.startsWith("concrt")||n.startsWith("ucrt"))
            return "MSVC_RUNTIME_DEPENDENCY";
        if(n.equals("steam_api64.dll")||n.startsWith("party")||
           n.equals("xgameruntime.dll"))
            return "GAME_PLATFORM_SERVICES";
        if(n.equals("kernel32.dll")||n.equals("user32.dll")||
           n.equals("advapi32.dll")||n.equals("gdi32.dll")||
           n.equals("ws2_32.dll")||n.equals("winhttp.dll")||
           n.equals("bcrypt.dll")||n.equals("crypt32.dll")||
           n.equals("shell32.dll")||n.equals("ole32.dll")||
           n.equals("oleaut32.dll")||n.equals("comctl32.dll")||
           n.equals("shlwapi.dll")||n.equals("mfplat.dll")||
           n.equals("xinput1_3.dll"))
            return "WINDOWS_SYSTEM_API";
        return "GAME_VENDOR_OR_OTHER";
    }
    public static Report assess(List<String> imported,Set<String> files,
                                boolean folderVerified) {
        if(imported==null)throw new IllegalArgumentException("import_list_null");
        Set<String> normalized=new LinkedHashSet<>();
        if(folderVerified) {
            if(files==null)throw new IllegalArgumentException("folder_files_null");
            for(String name:files)if(name!=null)
                normalized.add(name.toLowerCase(Locale.ROOT));
        }
        List<Entry> entries=new ArrayList<>();
        int local=0,missing=0,unknown=0,api=0;
        for(String raw:imported) {
            if(raw==null||!raw.matches("[A-Za-z0-9_.-]{1,128}"))
                throw new IllegalArgumentException("invalid_static_import_name");
            String n=raw.toLowerCase(Locale.ROOT),category=group(n);
            if(category.equals("WINDOWS_API_SET_CONTRACT"))api++;
            String state;
            if(!folderVerified){state=NOT_CHECKED;unknown++;}
            else if(normalized.contains(n)){state=LOCAL_PRESENT;local++;}
            else {state=NOT_LOCAL;missing++;}
            entries.add(new Entry(n,category,state));
        }
        return new Report(entries,local,missing,unknown,api);
    }
}
