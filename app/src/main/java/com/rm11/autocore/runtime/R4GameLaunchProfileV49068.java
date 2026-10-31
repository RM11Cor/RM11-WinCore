package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/** Shared runtime, but independent original EXE launch mode per game. */
public final class R4GameLaunchProfileV49068 {
    private R4GameLaunchProfileV49068(){}
    private static final String PREF="r4_v49068_per_exe_launch";
    public static final String DIRECT="DIRECT", LEGACY="LEGACY";
    public static String effectiveMode(String requested,boolean carx) {
        return LEGACY.equals(requested)?LEGACY:DIRECT;
    }
    private static String key(File exe) {
        if(exe==null)return null;
        try {
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(
                exe.getCanonicalPath().getBytes(StandardCharsets.UTF_8));
            StringBuilder s=new StringBuilder("launch_");
            for(int i=0;i<16;i++)s.append(String.format(Locale.ROOT,"%02x",digest[i]&255));
            return s.toString();
        }catch(Exception ignored){return null;}
    }
    public static String get(Context ctx,File exe) {
        boolean carx=exe!=null&&CarXStreetDxvkV49032.isSelectedCarXStreet(exe.toPath());
        String id=key(exe);
        if(ctx==null||id==null)return effectiveMode(DIRECT,carx);
        return effectiveMode(ctx.getSharedPreferences(PREF,0).getString(id,DIRECT),carx);
    }
    public static boolean save(Context ctx,File exe,String mode) {
        String id=key(exe);
        if(ctx==null||id==null||(!DIRECT.equals(mode)&&!LEGACY.equals(mode)))return false;
        return ctx.getSharedPreferences(PREF,0).edit().putString(id,mode).commit();
    }
    public static String label(String mode) {
        return LEGACY.equals(mode)?"نسخة خاصة مع XInput":"تشغيل ملف EXE الأصلي";
    }
}
