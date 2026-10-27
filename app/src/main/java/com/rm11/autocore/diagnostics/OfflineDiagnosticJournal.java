package com.rm11.autocore.diagnostics;

import android.content.Context;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;

/** App-private, bounded on-device diagnostic events. No network or root. */
public final class OfflineDiagnosticJournal {
    private static final int MAX_TEXT_PER_EVENT=11000;
    // Old v4.0.63 wrote ~18 * 11KB of pretty JSON then rejected the next
    // read if >210KB, resetting the entire history to one event.
    private static final int MAX_IMPORT_BYTES=550000;
    private static final String TAG="RM11-Diagnostics";
    private OfflineDiagnosticJournal() {}

    private static void atomicWrite(Path dir,String filename,String value)
            throws Exception {
        Path path=dir.resolve(filename),pending=dir.resolve(filename+".pending");
        if(Files.isSymbolicLink(dir)||Files.isSymbolicLink(path)
                ||Files.isSymbolicLink(pending))return;
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);
        try(FileOutputStream out=new FileOutputStream(pending.toFile())) {
            out.write(bytes);
            out.getFD().sync();
        }
        Files.move(pending,path,StandardCopyOption.REPLACE_EXISTING);
    }

    public static synchronized void record(Context context,String test,String report) {
        try {
            Path dir=new File(context.getFilesDir(),"offline-diagnostics").toPath();
            Files.createDirectories(dir);
            Path path=dir.resolve("events.json");
            if(Files.isSymbolicLink(path)||Files.isSymbolicLink(dir))return;
            JSONObject event=new JSONObject();
            event.put("timeUnixMs",System.currentTimeMillis());
            event.put("test",DiagnosticSanitizer.shortLabel(test));
            event.put("result",DiagnosticSanitizer.scrub(report,MAX_TEXT_PER_EVENT));

            // Game crash evidence is also persisted in two independent files.
            // Any subsequent live/exit/UI logging cannot overwrite them.
            if("v463-wine-assertion".equals(test)||"v463-assertion-final".equals(test))
                atomicWrite(dir,"last-game-assertion.json",event.toString());
            if("v462-first-seh-final".equals(test))
                atomicWrite(dir,"last-game-seh.json",event.toString());
            if("v465-native-abort-final".equals(test))
                atomicWrite(dir,"last-native-abort.json",event.toString());
            if("v466-adreno-driver-isolation".equals(test))
                atomicWrite(dir,"last-adreno-isolation.json",event.toString());
            if("v467-silksong-off-retest".equals(test))
                atomicWrite(dir,"last-v467-isolation.json",event.toString());
            if("v471-game-graphics-backend".equals(test))
                atomicWrite(dir,"last-graphics-backend.json",event.toString());
            if("v472-x11-wsi-child".equals(test))
                atomicWrite(dir,"last-v472-wsi.json",event.toString());
            if("v473-private-x11-vulkan".equals(test))
                atomicWrite(dir,"last-v473-private-vulkan.json",event.toString());
            if("v474-x11-vulkan-surface".equals(test))
                atomicWrite(dir,"last-v474-x11-surface.json",event.toString());
            if("v475-x11-vulkan-present".equals(test))
                atomicWrite(dir,"last-v475-x11-present.json",event.toString());
            if("v476-x11-dri3-audit".equals(test))
                atomicWrite(dir,"last-v476-x11-dri3.json",event.toString());
            if("v477-x11-swapchain-audit".equals(test)
                    &&report!=null&&report.contains("RM11_V477_CHILD_EXIT="))
                atomicWrite(dir,"last-v477-x11-swapchain.json",event.toString());
            if("v478-x11-software-wsi-audit".equals(test)
                    &&report!=null&&report.contains("RM11_V478_CHILD_EXIT="))
                atomicWrite(dir,"last-v478-x11-software-wsi.json",event.toString());
            if("v480-x11-touch-stability-audit".equals(test)
                    &&report!=null&&report.contains("RM11_V480_CHILD_EXIT="))
                atomicWrite(dir,"last-v480-x11-touch-stability.json",event.toString());
            // Game-only private Mesa selection must survive long game log rolls.
            if("v479-game-private-wsi".equals(test))
                atomicWrite(dir,"last-v479-game-wsi.json",event.toString());

            JSONArray existing=new JSONArray();
            if(Files.isRegularFile(path)) {
                long size=Files.size(path);
                if(size>0 && size<MAX_IMPORT_BYTES) {
                    try {
                        existing=new JSONArray(new String(Files.readAllBytes(path),
                                StandardCharsets.UTF_8));
                    }catch(Exception parseError) {
                        Log.w(TAG,"Malformed journal, independent crash evidence retained");
                    }
                }else if(size>=MAX_IMPORT_BYTES) {
                    Log.w(TAG,"Oversized old journal, independent crash evidence retained");
                }
            }
            ArrayList<String> candidates=new ArrayList<>();
            int from=Math.max(0,existing.length()-DiagnosticJournalBudget.MAX_EVENTS);
            for(int i=from;i<existing.length();i++) {
                JSONObject item=existing.optJSONObject(i);
                if(item!=null)candidates.add(item.toString());
            }
            candidates.add(event.toString());
            atomicWrite(dir,"events.json",
                    DiagnosticJournalBudget.lastCompleteEvents(candidates));
        }catch(Exception failure) {
            Log.w(TAG,"Unable to save event: "+failure.getClass().getSimpleName());
        }
    }
}
