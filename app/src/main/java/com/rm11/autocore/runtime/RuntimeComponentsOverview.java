package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Read-only component inventory. Native libraries are not interchangeable:
 * DXVK, VKD3D and Mesa Turnip must be packaged, verified and wired up before
 * they can be claimed as installed or ready for games.
 */
public final class RuntimeComponentsOverview {
    private RuntimeComponentsOverview() {}
    private static String check(Path path) {
        return Files.isRegularFile(path) && Files.isReadable(path)
                ? "موجود ضمن المحاكي" : "غير جاهز";
    }
    public static String inspect(Context context) {
        RuntimeLayout p=new RuntimeLayout(context.getFilesDir().toPath(),
                new File(context.getApplicationInfo().nativeLibraryDir).toPath());
        return "وضع الألعاب المباشر — بدون سطح مكتب Windows\n\n"
                +"Wine Launcher: "+check(p.nativeWineLauncher)+"\n"
                +"WineServer: "+check(p.nativeWineServer)+"\n"
                +"Wine Prefix: "+(Files.isRegularFile(p.winePrefixMarker())
                    ?"مهيأ مسبقاً":"غير مهيأ بعد")+"\n"
                +"FEX ARM64EC: "+check(p.fexArm64ec())+"\n"
                +"FEX WoW64: "+check(p.fexWow64())+"\n"
                +"X11 / Lorie: "+check(p.apkNativeLibs.resolve("libXlorie.so"))+"\n"
                +"Wine X11: "+check(p.apkNativeLibs.resolve("libwine_winex11.so"))+"\n"
                +"Vulkan Android: يحتاج اختبار GPU فعلي\n"
                +"DXVK: افتح فحص الحزم المرفق؛ التشغيل داخل Wine غير مفعّل\n"
                +"VKD3D-Proton: افتح فحص الحزم المرفق؛ التشغيل داخل Wine غير مفعّل\n"
                +"Mesa Turnip: لم يُتحقق من تثبيت تعريف بديل\n\n"
                +"الموجود لا يعني أنه اجتاز التشغيل على جهازك. "
                +"هذه شاشة جرد فقط، ولا تحمّل تعريفات من الإنترنت ولا تغيّر ملفات الألعاب.";
    }
}
