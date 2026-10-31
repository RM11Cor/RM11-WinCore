package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Persistent, per-original-EXE launch handoff evidence.
 * A successful Android Activity handoff is NEVER evidence that a Windows
 * game started, displayed frames or accepted controller input.
 * Stores only a SHA256-derived key, event status and coarse timestamp.
 * Original paths, game files and Wine prefixes are never modified. */
public final class KernixLaunchAttemptsV49084 {
    private KernixLaunchAttemptsV49084(){}
    private static final String PREF="kernix_v49084_launch_attempts";
    public static final String NONE="NO_ATTEMPT";
    public static final String SOURCE_BLOCKED="SOURCE_BLOCKED";
    public static final String COMPONENT_BLOCKED="COMPONENT_BLOCKED";
    public static final String PERMISSION_REQUIRED="PERMISSION_REQUIRED";
    public static final String VALIDATION_FAILED="VALIDATION_FAILED";
    public static final String ACTIVITY_DISPATCHED="ACTIVITY_DISPATCHED";
    public static final String ACTIVITY_FAILED="ACTIVITY_FAILED";
    public static String description(String state){
        if(SOURCE_BLOCKED.equals(state))return "توقف قبل التشغيل: ملف اللعبة غير متاح";
        if(COMPONENT_BLOCKED.equals(state))return "توقف قبل التشغيل: مكوّن مطلوب غير جاهز";
        if(PERMISSION_REQUIRED.equals(state))return "بانتظار صلاحية قراءة ملفات اللعبة";
        if(VALIDATION_FAILED.equals(state))return "تعذر تجهيز أو التحقق من مسار التشغيل";
        if(ACTIVITY_DISPATCHED.equals(state))return "انرسلت محاولة التشغيل إلى Wine — نجاح اللعبة غير مثبت";
        if(ACTIVITY_FAILED.equals(state))return "تعذر فتح واجهة تشغيل Wine";
        return "ماكو محاولة تشغيل مسجلة";
    }
    private static boolean recognized(String state){
        return SOURCE_BLOCKED.equals(state)||COMPONENT_BLOCKED.equals(state)
            ||PERMISSION_REQUIRED.equals(state)||VALIDATION_FAILED.equals(state)
            ||ACTIVITY_DISPATCHED.equals(state)||ACTIVITY_FAILED.equals(state);
    }
    private static String key(File original) {
        if(original==null)return null;
        try {
            String path=original.getCanonicalPath();
            byte[] digest=MessageDigest.getInstance("SHA-256")
                .digest(path.getBytes(StandardCharsets.UTF_8));
            StringBuilder result=new StringBuilder("game_");
            for(int i=0;i<16;i++)
                result.append(String.format(Locale.ROOT,"%02x",digest[i]&0xff));
            return result.toString();
        }catch(Exception ignored){return null;}
    }
    public static void record(Context context,File original,String state){
        if(context==null||!recognized(state))return;
        String k=key(original);
        if(k==null)return;
        SharedPreferences pref=context.getSharedPreferences(PREF,Context.MODE_PRIVATE);
        pref.edit().putString(k+"_status",state)
            .putLong(k+"_time",System.currentTimeMillis()).apply();
    }
    public static JSONObject snapshot(Context context,File original){
        JSONObject result=new JSONObject();
        String k=key(original);
        String state=NONE;
        long when=0;
        if(context!=null&&k!=null){
            SharedPreferences pref=context.getSharedPreferences(PREF,Context.MODE_PRIVATE);
            state=pref.getString(k+"_status",NONE);
            when=pref.getLong(k+"_time",0);
        }
        if(!recognized(state))state=NONE;
        try{
            result.put("state",state);
            result.put("description",description(state));
            result.put("when",when);
            result.put("gameplayProven",false);
            result.put("framePresentationProven",false);
        }catch(Exception ignored){}
        return result;
    }
}
