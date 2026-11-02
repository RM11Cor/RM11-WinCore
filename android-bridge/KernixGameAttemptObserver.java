package com.winlator.star.kernix;

import android.content.Context;
import android.os.Process;
import android.util.Log;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/** A narrowly scoped session-start breadcrumb. Does NOT verify EXE launch. */
public final class KernixGameAttemptObserver {
    private static final String TAG="KernixGameAttempt";
    private static final String FILE="kernix-game-attempts.jsonl";
    private KernixGameAttemptObserver(){}

    public static void sessionServiceStarted(Context context, String shortcutLabel) {
        try {
            if(shortcutLabel==null || shortcutLabel.trim().isEmpty())return;
            String name=shortcutLabel.trim();
            if(name.length()>120)name=name.substring(0,120);
            JSONObject event=new JSONObject();
            event.put("schema","kernix.session-service-start.v1");
            event.put("source","GameSessionForegroundService.onStartCommand");
            event.put("shortcut_label",name);
            event.put("android_pid",Process.myPid());
            event.put("wall_clock_ms",System.currentTimeMillis());
            event.put("guest_exe_started",JSONObject.NULL);
            event.put("fex_version_verified",JSONObject.NULL);
            event.put("vkd3d_device_created",JSONObject.NULL);
            event.put("first_frame_verified",JSONObject.NULL);
            File file=new File(context.getFilesDir(),FILE);
            if(file.exists() && file.length()>256*1024) {
                // Bound the journal; no delete of game logs or user data.
                if(!file.delete())return;
            }
            byte[] bytes=(event.toString()+"\n").getBytes(StandardCharsets.UTF_8);
            try(FileOutputStream stream=new FileOutputStream(file,true)){
                stream.write(bytes);stream.flush();stream.getFD().sync();
            }
        }catch(Exception e){Log.w(TAG,"Could not record session-start breadcrumb",e);}
    }
}
