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
            if("v480-probe-after-touch".equals(test))
                atomicWrite(dir,"last-v480-touch-pixels.json",event.toString());
            // Game-only private Mesa selection must survive long game log rolls.
            if("v479-game-private-wsi".equals(test))
                atomicWrite(dir,"last-v479-game-wsi.json",event.toString());
            // v482: game live events roll over quickly while user waits on a
            // black screen. Preserve read-only X11/window and touch evidence.
            if("v482-game-window-state".equals(test))
                atomicWrite(dir,"last-v482-game-window.json",event.toString());
            if("v482-game-window-final".equals(test))
                atomicWrite(dir,"last-v482-game-window-final.json",event.toString());
            if("v457-game-no-window".equals(test))
                atomicWrite(dir,"last-v482-no-window-trigger.json",event.toString());
            if("v482-game-touch-baseline".equals(test))
                atomicWrite(dir,"last-v482-game-touch-baseline.json",event.toString());
            if("v482-game-touch-after".equals(test))
                atomicWrite(dir,"last-v482-game-touch-after.json",event.toString());
            if("v483-game-window-recovery".equals(test))
                atomicWrite(dir,"last-v483-game-window-recovery.json",event.toString());
            if("v484-window-inventory".equals(test))
                atomicWrite(dir,"last-v484-window-inventory.json",event.toString());
            if("v484-first-window-inventory".equals(test))
                atomicWrite(dir,"last-v484-first-window-inventory.json",event.toString());
            if("v484-window-recovery-decision".equals(test))
                atomicWrite(dir,"last-v484-window-recovery-decision.json",event.toString());
            if("v485-game-launch-args".equals(test))
                atomicWrite(dir,"last-v485-game-launch-args.json",event.toString());
            if("v49032-carx-private-dxvk".equals(test))
                atomicWrite(dir,"last-v49033-carx-vulkan-route.json",event.toString());
            if("v49033-carx-runtime-plan".equals(test))
                atomicWrite(dir,"last-v49033-carx-runtime-plan.json",event.toString());
            if("v49034-carx-sidecar".equals(test))
                atomicWrite(dir,"last-v49034-carx-sidecar.json",event.toString());
            if("v49034-carx-effective-command".equals(test))
                atomicWrite(dir,"last-v49034-carx-effective-command.json",event.toString());
            if("v49038-controller-status".equals(test))
                atomicWrite(dir,"last-v49038-controller-status.json",event.toString());
            if("v49038-xinput-stage".equals(test))
                atomicWrite(dir,"last-v49038-xinput-stage.json",event.toString());
            // Preserve controller events even if long-running Wine traces rotate events.json.
            if("v49040-input-touch".equals(test))
                atomicWrite(dir,"last-v49041-touch-input.json",event.toString());
            if("v49040-input-route".equals(test))
                atomicWrite(dir,"last-v49041-keyboard-transport.json",event.toString());
            if("v49039-universal-pad".equals(test))
                atomicWrite(dir,"last-v49041-controller-profile.json",event.toString());
            if("v49042-pad-hotplug".equals(test))
                atomicWrite(dir,"last-v49042-pad-hotplug.json",event.toString());
            if("v49044-winebus-probe".equals(test))
                atomicWrite(dir,"last-v49044-winebus-probe.json",event.toString());
            if("v49045-winebus-session".equals(test))
                atomicWrite(dir,"last-v49045-winebus-session.json",event.toString());
            if("v49046-sdl-dependency".equals(test))
                atomicWrite(dir,"last-v49046-sdl-dependency.json",event.toString());
            if("v49047-touch-recovery".equals(test))
                atomicWrite(dir,"last-v49047-touch-recovery.json",event.toString());
            if("v49048-winedevice-bus".equals(test))
                atomicWrite(dir,"last-v49048-winedevice-bus.json",event.toString());
            // Preserve XInput setup evidence even when events.json rotates.
            if("v49049-universal-xinput".equals(test))
                atomicWrite(dir,"last-v49049-universal-xinput.json",event.toString());
            if("v49051-app-local-xinput".equals(test))
                atomicWrite(dir,"last-v49051-app-local-xinput.json",event.toString());
            if("v49051-controller-activation".equals(test))
                atomicWrite(dir,"last-v49051-controller-activation.json",event.toString());
            if("v49051-winebus-isolation".equals(test))
                atomicWrite(dir,"last-v49051-winebus-isolation.json",event.toString());
            if("v49053-game-xinput-audit".equals(test))
                atomicWrite(dir,"last-v49053-game-xinput-audit.json",event.toString());
            if("v49054-winebus-activation".equals(test))
                atomicWrite(dir,"last-v49054-winebus-activation.json",event.toString());
            if("v49055-winebus-propagation".equals(test))
                atomicWrite(dir,"last-v49055-winebus-propagation.json",event.toString());
            if("v49055-game-winebus-env".equals(test))
                atomicWrite(dir,"last-v49055-game-winebus-env.json",event.toString());
            if("v49057-native-winebus-install".equals(test))
                atomicWrite(dir,"last-v49057-native-winebus-install.json",event.toString());
            if("v49057-native-hid-activation".equals(test))
                atomicWrite(dir,"last-v49057-native-hid-activation.json",event.toString());
            if("v49073-vkd3d-dx12-route".equals(test))
                atomicWrite(dir,"last-v49073-vkd3d-route.json",event.toString());
            if("v49066-game-component-profile".equals(test))
                atomicWrite(dir,"last-v49066-graphics-profile.json",event.toString());
            if("v49071-automatic-component-plan".equals(test))
                atomicWrite(dir,"last-v49071-graphics-auto.json",event.toString());
            if("v49074-dx12-start".equals(test))
                atomicWrite(dir,"last-v49074-dx12-start.json",event.toString());
            if("v49074-dx12-evidence-first".equals(test))
                atomicWrite(dir,"last-v49074-dx12-first.json",event.toString());
            if("v49074-dx12-evidence-live".equals(test))
                atomicWrite(dir,"last-v49074-dx12-live.json",event.toString());
            if("v49074-dx12-evidence-final".equals(test))
                atomicWrite(dir,"last-v49074-dx12-final.json",event.toString());
            if("v486-game-startup-first".equals(test))
                atomicWrite(dir,"last-v486-game-startup-first.json",event.toString());
            if("v486-game-startup-final".equals(test))
                atomicWrite(dir,"last-v486-game-startup-final.json",event.toString());
            if("v487-game-process-activity-first".equals(test))
                atomicWrite(dir,"last-v487-game-process-first.json",event.toString());
            if("v487-game-process-activity".equals(test))
                atomicWrite(dir,"last-v487-game-process-live.json",event.toString());
            if("v487-game-process-activity-final".equals(test))
                atomicWrite(dir,"last-v487-game-process-final.json",event.toString());
            if("v488-wine-native-census-first".equals(test))
                atomicWrite(dir,"last-v488-wine-native-first.json",event.toString());
            if("v488-wine-native-census".equals(test))
                atomicWrite(dir,"last-v488-wine-native-live.json",event.toString());
            if("v488-wine-native-census-final".equals(test))
                atomicWrite(dir,"last-v488-wine-native-final.json",event.toString());
            if("v489-native-activity-first".equals(test))
                atomicWrite(dir,"last-v489-native-first.json",event.toString());
            if("v489-native-activity".equals(test))
                atomicWrite(dir,"last-v489-native-live.json",event.toString());
            if("v489-native-activity-final".equals(test))
                atomicWrite(dir,"last-v489-native-final.json",event.toString());

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
