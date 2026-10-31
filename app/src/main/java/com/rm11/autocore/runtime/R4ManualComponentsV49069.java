package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.util.Locale;

/** R4 manual per-game selection. Only truly bundled versions are activatable;
 * other historical/new version rows are disabled until their binaries exist.
 * No game-name based presets, no downloading unverified executables. */
public final class R4ManualComponentsV49069 {
    private R4ManualComponentsV49069(){}
    private static final String PREF="r4_v49069_manual_components";
    public static final String WINE="WINE",FEX="FEX",GRAPHICS="GRAPHICS",
        VKD3D="VKD3D",VULKAN="VULKAN",X11="X11",LAUNCH="LAUNCH";
    public static final String[] SLOTS={WINE,FEX,GRAPHICS,VKD3D,VULKAN,X11,LAUNCH};
    public static final String[] NAMES={"Wine","FEX","DXVK / WineD3D","VKD3D-Proton",
        "Turnip / Vulkan","X11","ملف EXE"};

    public static final class Version {
        public final String id,name,detail;
        public final boolean installed;
        public Version(String id,String name,boolean installed,String detail) {
            this.id=id;this.name=name;this.installed=installed;this.detail=detail;
        }
        public String label(){return name+(installed?" [مثبت]":" [غير مثبت]");}
    }
    private static boolean ok(java.nio.file.Path p) {
        try{return Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
            &&!Files.isSymbolicLink(p)&&Files.size(p)>4096;}
        catch(Exception ignored){return false;}
    }
    private static String prefKey(File exe,String slot) {
        if(exe==null)return null;
        try {
            byte[] b=MessageDigest.getInstance("SHA-256").digest(
                exe.getCanonicalPath().getBytes(StandardCharsets.UTF_8));
            StringBuilder s=new StringBuilder(slot+"_");
            for(int i=0;i<16;i++)s.append(String.format(Locale.ROOT,"%02x",b[i]&255));
            return s.toString();
        }catch(Exception ignored){return null;}
    }
    public static Version[] versions(Context ctx,String slot) {
        RuntimeLayout r=new RuntimeLayout(ctx.getFilesDir().toPath(),
            new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
        boolean wine=ok(r.nativeWineLauncher)&&ok(r.nativeWineServer)&&ok(r.nativeNtdll);
        boolean fex=ok(r.fexArm64ec())&&ok(r.fexWow64());
        boolean x11=ok(r.apkNativeLibs.resolve("libwine_winex11.so"));
        boolean wsi=ok(r.apkNativeLibs.resolve("librm11_vkloader_v473.so"))
            &&ok(r.apkNativeLibs.resolve("librm11_vkdriver_v473.so"))
            &&ok(r.apkNativeLibs.resolve("librm11_v49028_mini_x11_vulkan.so"));
        if(WINE.equals(slot))return new Version[]{
            new Version("WINE_BUNDLED","Wine 11 ARM64EC",wine,"المحرك المدمج"),
            new Version("WINE_10","Wine 10",false,"ملفاته غير مثبتة"),
            new Version("WINE_9","Wine 9",false,"ملفاته غير مثبتة")};
        if(FEX.equals(slot))return new Version[]{
            new Version("FEX_BUNDLED","FEX ARM64EC / WoW64 المدمج",fex,"المحرك الحالي"),
            new Version("FEX_OLD","FEX إصدار أقدم",false,"غير مثبت"),
            new Version("FEX_NEW","FEX إصدار أحدث",false,"غير مثبت")};
        if(GRAPHICS.equals(slot))return new Version[]{
            new Version("WINED3D","WineD3D — Wine المدمج",wine,"للألعاب المتوافقة"),
            new Version("DXVK","DXVK x64 — الحزمة الموقعة",
                R4GameRuntimeConfigV49066.hasApkDxvk(ctx),"تجريبي؛ يحتاج X11 software WSI"),
            new Version("DXVK_2","DXVK 2.x قديم",false,"غير مثبت"),
            new Version("DXVK_3_OTHER","DXVK 3.x آخر",false,"غير مثبت")};
        if(VKD3D.equals(slot))return new Version[]{
            new Version("VKD3D_OFF","بدون VKD3D",true,"لا يفعل Direct3D 12"),
            new Version("VKD3D_2","VKD3D-Proton 2.x",false,"مكونات صالحة غير مثبتة"),
            new Version("VKD3D_3","VKD3D-Proton 3.x",false,"غير مثبت")};
        if(VULKAN.equals(slot))return new Version[]{
            new Version("VULKAN_OFF","بدون تعريف Vulkan خاص",true,"مسار WineD3D"),
            new Version("X11_SW","X11 software WSI — تجريبي",wsi,
                "موجود لكن لا يثبت الوصول إلى GPU"),
            new Version("TURNIP_OLD","Turnip قديم",false,"غير مثبت للعب العتادي"),
            new Version("TURNIP_NEW","Turnip حديث",false,"غير مثبت للعب العتادي")};
        if(X11.equals(slot))return new Version[]{
            new Version("X11_BUNDLED","X11 المدمج",x11,"المسار الموجود"),
            new Version("X11_OLD","X11 قديم",false,"غير مثبت")};
        if(LAUNCH.equals(slot))return new Version[]{
            new Version("DIRECT","EXE الأصلي مباشرة",true,"مجلد اللعبة الأصلي"),
            new Version("LEGACY","EXE نسخة خاصة",true,"مسار توافق XInput")};
        return new Version[0];
    }
    public static String defaultFor(String slot){
        if(WINE.equals(slot))return "WINE_BUNDLED";
        if(FEX.equals(slot))return "FEX_BUNDLED";
        if(GRAPHICS.equals(slot))return "WINED3D";
        if(VKD3D.equals(slot))return "VKD3D_OFF";
        if(VULKAN.equals(slot))return "VULKAN_OFF";
        if(X11.equals(slot))return "X11_BUNDLED";
        return "DIRECT";
    }
    public static String get(Context ctx,File exe,String slot){
        if(GRAPHICS.equals(slot)){
            String mode=R4GameRuntimeConfigV49066.get(ctx,exe);
            return "DXVK".equals(mode)?"DXVK":"WINED3D";
        }
        if(LAUNCH.equals(slot))return R4GameLaunchProfileV49068.get(ctx,exe);
        String key=prefKey(exe,slot);
        return ctx==null||key==null?defaultFor(slot):
            ctx.getSharedPreferences(PREF,0).getString(key,defaultFor(slot));
    }
    public static boolean save(Context ctx,File exe,String slot,String id){
        if(ctx==null||exe==null||slot==null||id==null)return false;
        boolean allowed=false;
        for(Version v:versions(ctx,slot))if(v.id.equals(id)&&v.installed)allowed=true;
        if(!allowed)return false;
        if(GRAPHICS.equals(slot))return R4GameRuntimeConfigV49066.save(ctx,exe,id);
        if(LAUNCH.equals(slot))return R4GameLaunchProfileV49068.save(ctx,exe,id);
        String key=prefKey(exe,slot);
        return key!=null&&ctx.getSharedPreferences(PREF,0).edit().putString(key,id).commit();
    }
    public static void requireInstalled(Context ctx,File exe)throws java.io.IOException{
        for(String slot:SLOTS){
            boolean installed=false;String selected=get(ctx,exe,slot);
            for(Version v:versions(ctx,slot))
                if(v.installed&&v.id.equals(selected))installed=true;
            if(!installed)throw new java.io.IOException(
                "R4_MANUAL_VERSION_NOT_INSTALLED:"+slot+":"+selected);
        }
        if("DXVK".equals(get(ctx,exe,GRAPHICS))
           &&!"X11_SW".equals(get(ctx,exe,VULKAN)))
            throw new java.io.IOException("R4_SELECT_X11_SW_MANUALLY_FOR_DXVK");
        if("WINED3D".equals(get(ctx,exe,GRAPHICS))
           &&!"VULKAN_OFF".equals(get(ctx,exe,VULKAN)))
            throw new java.io.IOException("R4_SELECT_VULKAN_OFF_MANUALLY_FOR_WINED3D");
    }
    public static String summary(Context ctx,File exe){
        StringBuilder out=new StringBuilder();
        for(int i=0;i<SLOTS.length;i++){
            String id=get(ctx,exe,SLOTS[i]), label=id;
            for(Version v:versions(ctx,SLOTS[i]))
                if(v.id.equals(id)){label=v.label();break;}
            out.append(NAMES[i]).append(": ").append(label).append('\n');
        }
        return out.toString();
    }
}
