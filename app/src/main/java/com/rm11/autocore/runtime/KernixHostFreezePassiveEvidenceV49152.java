package com.rm11.autocore.runtime;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.os.PowerManager;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;

/**
 * Passive, bounded Android-only snapshot, collected on explicit ZIP export.
 * Absolutely NO Wine, FEX, X.Org, Vulkan, child-process launch, game read,
 * logcat access, shell, root or background polling.
 *
 * Warning: all memory/thermal values are measured at EXPORT time, and
 * historical exit reasons are NOT proof of a system-wide device freeze.
 */
public final class KernixHostFreezePassiveEvidenceV49152 {
    private KernixHostFreezePassiveEvidenceV49152() {}
    public static JSONObject snapshot(Context context) {
        JSONObject root=new JSONObject();
        try {
            root.put("schema","kernix.host-freeze-passive.v49152");
            root.put("capturedAtUnixMs",System.currentTimeMillis());
            root.put("allLiveMeasurementsAreAtExportOnly",true);
            root.put("freezeMomentMeasurementsAvailable",false);
            root.put("didStartAnyRuntimeOrTest",false);
            root.put("historicalAppExitIsNotDeviceFreezeProof",true);
            root.put("noRootNoLogcatNoUserGameFiles",true);
            if(context==null){
                root.put("result","NO_CONTEXT");
                return root;
            }
            Context app=context.getApplicationContext();
            if(app==null)app=context;
            ActivityManager am=(ActivityManager)app.getSystemService(Context.ACTIVITY_SERVICE);
            JSONObject memory=new JSONObject();
            if(am!=null) {
                try {
                    ActivityManager.MemoryInfo info=new ActivityManager.MemoryInfo();
                    am.getMemoryInfo(info);
                    memory.put("availableBytesAtExport",info.availMem);
                    memory.put("totalBytesAtExport",info.totalMem);
                    memory.put("lowMemoryThresholdBytes",info.threshold);
                    memory.put("lowMemoryAtExport",info.lowMemory);
                }catch(Exception e){
                    memory.put("systemMemoryRead","UNAVAILABLE_"+e.getClass().getSimpleName());
                }
            }else memory.put("systemMemoryRead","SERVICE_UNAVAILABLE");
            try{
                Debug.MemoryInfo own=new Debug.MemoryInfo();
                Debug.getMemoryInfo(own);
                memory.put("ownAppTotalPssKbAtExport",own.getTotalPss());
                memory.put("ownAppNativePssKbAtExport",own.nativePss);
            }catch(Exception e){
                memory.put("appMemoryRead","UNAVAILABLE_"+e.getClass().getSimpleName());
            }
            root.put("memory",memory);
            JSONObject thermal=new JSONObject();
            thermal.put("measurementTime","EXPORT_NOT_FREEZE");
            if(Build.VERSION.SDK_INT>=29){
                try {
                    PowerManager pm=(PowerManager)app.getSystemService(Context.POWER_SERVICE);
                    if(pm!=null)thermal.put("androidThermalStatusAtExport",pm.getCurrentThermalStatus());
                    else thermal.put("read","POWER_MANAGER_UNAVAILABLE");
                }catch(Exception e){
                    thermal.put("read","UNAVAILABLE_"+e.getClass().getSimpleName());
                }
            }else thermal.put("read","SDK_UNSUPPORTED");
            root.put("thermal",thermal);
            JSONArray exits=new JSONArray();
            if(Build.VERSION.SDK_INT>=30 && am!=null){
                try {
                    List<ApplicationExitInfo> history=am.getHistoricalProcessExitReasons(null,0,12);
                    if(history!=null){
                        String pkg=app.getPackageName();
                        for(ApplicationExitInfo entry:history) {
                            if(exits.length()>=12)break;
                            String name=entry.getProcessName();
                            if(!pkg.equals(name) && !(pkg+":rm11_xorg").equals(name))continue;
                            JSONObject item=new JSONObject();
                            item.put("appProcess",pkg.equals(name)?"MAIN_APP":"XORG_SERVICE");
                            item.put("timeUnixMs",entry.getTimestamp());
                            item.put("reason",entry.getReason());
                            item.put("status",entry.getStatus());
                            item.put("importance",entry.getImportance());
                            item.put("pssKbWhenRecorded",entry.getPss());
                            item.put("rssKbWhenRecorded",entry.getRss());
                            item.put("interpretation",KernixHostFreezeExitReasonV49152.classify(entry.getReason()));
                            exits.put(item);
                        }
                    }
                    root.put("exitHistoryStatus","READ_WITH_LIMIT");
                }catch(Exception e){
                    root.put("exitHistoryStatus","UNAVAILABLE_"+e.getClass().getSimpleName());
                }
            }else root.put("exitHistoryStatus","SDK_OR_SERVICE_UNAVAILABLE");
            root.put("appProcessExitHistory",exits);
        }catch(Exception e){
            try{root.put("snapshotError",e.getClass().getSimpleName());}
            catch(Exception ignored){}
        }
        return root;
    }
}
