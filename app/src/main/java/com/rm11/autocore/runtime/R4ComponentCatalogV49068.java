package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Read-only component inventory; files are NOT proof of working gameplay. */
public final class R4ComponentCatalogV49068 {
    private R4ComponentCatalogV49068(){}
    private static boolean exists(Path p,long min) {
        try{return Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
            &&!Files.isSymbolicLink(p)&&Files.size(p)>=min;
        }catch(Exception ignored){return false;}
    }
    private static boolean asset(Context ctx,String path) {
        try(InputStream in=ctx.getAssets().open(path)){return in.read()>=0;}
        catch(Exception ignored){return false;}
    }
    private static String state(boolean present) {
        return present?"ملفاته موجودة (تشغيله غير مثبت)":"مكوناته غير مكتملة";
    }
    public static String describe(Context ctx,File exe) {
        if(ctx==null)return "فحص المكونات غير متاح";
        RuntimeLayout r=new RuntimeLayout(ctx.getFilesDir().toPath(),
            new File(ctx.getApplicationInfo().nativeLibraryDir).toPath());
        boolean wine=exists(r.nativeWineLauncher,4096)
            &&exists(r.nativeWineServer,4096)&&exists(r.nativeNtdll,4096)
            &&exists(r.winePrefixMarker(),0);
        boolean fex=exists(r.fexArm64ec(),4096)&&exists(r.fexWow64(),4096);
        boolean x11=exists(r.apkNativeLibs.resolve("libwine_winex11.so"),4096);
        boolean dxvk=asset(ctx,"engine/providers/dxvk/x64/d3d11.dll")
            &&asset(ctx,"engine/providers/dxvk/x64/dxgi.dll");
        return "مكونات المحرك المشتركة — R4 v4.90.68\n\n"
            +"Wine: "+state(wine)+"\n"
            +"FEX/ARM64EC: "+state(fex)+"\n"
            +"X11: "+state(x11)+"؛ عرض اللعبة غير مثبت\n"
            +"DXVK: "+state(dxvk)+"؛ تجريبي\n"
            +"VKD3D-Proton: غير مفعل حالياً\n"
            +"Turnip/Vulkan العتادي: موجود كمسار مرحلي؛ الإطار غير مثبت\n"
            +"Winebus/XInput: نظام مشترك؛ استجابة الألعاب غير مثبتة\n\n"
            +"هذه اللعبة:\n"
            +"طريقة التشغيل: "+R4GameLaunchProfileV49068.label(
                R4GameLaunchProfileV49068.get(ctx,exe))+"\n"
            +"الرسوميات: "+R4GameRuntimeConfigV49066.label(
                R4GameRuntimeConfigV49066.get(ctx,exe))+"\n\n"
            +"وجود الملفات ما يثبت عمل اللعبة ولا تشغيل GPU.\n"
            +"ما عدّلنا ملفات اللعبة أو Wine prefix.";
    }
}
