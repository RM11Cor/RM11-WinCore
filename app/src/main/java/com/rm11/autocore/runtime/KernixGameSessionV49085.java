package com.rm11.autocore.runtime;
import android.content.Context;
import android.content.SharedPreferences;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;
import org.json.JSONObject;

/** Read-only game-session evidence keyed by ORIGINAL library EXE and UUID.
 * A Wine process or an X11 root child does NOT prove that this Windows game
 * opened a window or presented pixels to the Android display. */
public final class KernixGameSessionV49085 {
    private KernixGameSessionV49085(){}
    private static final String PREF="kernix_v49085_game_session";
    public static final String NONE="NO_SESSION",DISPATCHED="DISPATCHED",
        X11_READY="X11_ENDPOINT_READY",PROCESS_CREATED="WINE_LAUNCHER_CREATED",
        X11_CHILD="X11_ROOT_CHILD_SEEN",NO_WINDOW="NO_X11_CHILD_16S",
        PROCESS_EXITED="WINE_LAUNCHER_EXITED",ENGINE_ERROR="ENGINE_ERROR",
        LAUNCHER_ZOMBIE="NATIVE_LAUNCHER_ZOMBIE",
        SESSION_CLOSED="SESSION_CLOSED";
    private static String key(File game){
        if(game==null)return null;
        try{
            byte[] sha=MessageDigest.getInstance("SHA-256").digest(
                game.getCanonicalPath().getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder("game_");
            for(int i=0;i<16;i++)out.append(
                String.format(Locale.ROOT,"%02x",sha[i]&255));
            return out.toString();
        }catch(Exception ignored){return null;}
    }
    private static boolean valid(String phase){
        return DISPATCHED.equals(phase)||X11_READY.equals(phase)
            ||PROCESS_CREATED.equals(phase)||X11_CHILD.equals(phase)
            ||NO_WINDOW.equals(phase)||PROCESS_EXITED.equals(phase)
            ||ENGINE_ERROR.equals(phase)||SESSION_CLOSED.equals(phase)
            ||LAUNCHER_ZOMBIE.equals(phase);
    }
    public static String label(String phase){
        if(DISPATCHED.equals(phase))return "طلب تشغيل أُرسل إلى Wine";
        if(X11_READY.equals(phase))return "اتصال X11 جاهز، صورة اللعبة غير مثبتة";
        if(PROCESS_CREATED.equals(phase))return "مشغّل Wine بدأ، تشغيل اللعبة غير مثبت";
        if(X11_CHILD.equals(phase))return "نافذة X11 عامة، ملكيتها للعبة غير مثبتة";
        if(NO_WINDOW.equals(phase))return "ما ظهرت نافذة X11 في آخر فحص";
        if(PROCESS_EXITED.equals(phase))return "مشغّل Wine خرج؛ افحص رمز الخروج";
        if(LAUNCHER_ZOMBIE.equals(phase))return "عملية المشغّل بحالة Zombie؛ وجود Wine آخر لا يثبت تشغيل اللعبة";
        if(ENGINE_ERROR.equals(phase))return "خطأ أثناء تجهيز أو تنفيذ Wine";
        if(SESSION_CLOSED.equals(phase))return "الجلسة انتهت، عرض اللعبة غير مثبت";
        return "ماكو جلسة مسجلة";
    }
    public static String begin(Context ctx,File original){
        if(ctx==null)return null;String k=key(original);if(k==null)return null;
        String token=UUID.randomUUID().toString();
        boolean saved=ctx.getSharedPreferences(PREF,Context.MODE_PRIVATE).edit()
            .putString(k+"_id",token).putString(k+"_phase",DISPATCHED)
            .putLong(k+"_when",System.currentTimeMillis())
            .putLong(k+"_elapsed",0)
            .putBoolean(k+"_x11",false).putBoolean(k+"_vkerror",false)
            .putInt(k+"_exit",Integer.MIN_VALUE).commit();
        return saved?token:null;
    }
    public static boolean matches(Context ctx,File original,String token){
        String k=key(original);
        return ctx!=null&&k!=null&&token!=null&&!token.isEmpty()
            &&token.equals(ctx.getSharedPreferences(PREF,0).getString(k+"_id",""));
    }
    public static synchronized void observe(Context ctx,File original,String token,
            String phase,boolean rootChild,boolean vulkanError,long elapsed,int exit){
        if(!valid(phase)||!matches(ctx,original,token))return;
        String k=key(original);
        SharedPreferences p=ctx.getSharedPreferences(PREF,0);
        // A zombie native loader must not be overwritten by a generic X11
        // root-child sample or normal session-close event. A specific
        // process exit/engine error still takes precedence.
        String existing=p.getString(k+"_phase",NONE);
        String effective=LAUNCHER_ZOMBIE.equals(existing)
            && !PROCESS_EXITED.equals(phase) && !ENGINE_ERROR.equals(phase)
            ?LAUNCHER_ZOMBIE:phase;
        p.edit().putString(k+"_phase",effective)
            .putLong(k+"_elapsed",Math.max(0,elapsed))
            .putBoolean(k+"_x11",p.getBoolean(k+"_x11",false)||rootChild)
            .putBoolean(k+"_vkerror",p.getBoolean(k+"_vkerror",false)||vulkanError)
            .putInt(k+"_exit",exit).commit();
    }
    public static JSONObject snapshot(Context ctx,File original){
        JSONObject result=new JSONObject();String k=key(original);
        String phase=NONE;long when=0,elapsed=0;
        boolean root=false,vk=false;int exit=Integer.MIN_VALUE;
        if(ctx!=null&&k!=null){
            SharedPreferences p=ctx.getSharedPreferences(PREF,0);
            phase=p.getString(k+"_phase",NONE);
            when=p.getLong(k+"_when",0);elapsed=p.getLong(k+"_elapsed",0);
            root=p.getBoolean(k+"_x11",false);
            vk=p.getBoolean(k+"_vkerror",false);
            exit=p.getInt(k+"_exit",Integer.MIN_VALUE);
        }
        if(!valid(phase))phase=NONE;
        try{
            result.put("phase",phase);result.put("description",label(phase));
            result.put("when",when);result.put("elapsedMs",elapsed);
            result.put("anyX11RootWindowObserved",root);
            result.put("vulkanFailureSignalObserved",vk);
            result.put("supervisedWineExitCode",
                exit==Integer.MIN_VALUE?JSONObject.NULL:exit);
            result.put("selectedGameWindowOwnershipProven",false);
            result.put("androidGameFrameProven",false);
        }catch(Exception ignored){}
        return result;
    }
}
