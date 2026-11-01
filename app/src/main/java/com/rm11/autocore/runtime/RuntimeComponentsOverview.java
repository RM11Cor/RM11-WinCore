package com.rm11.autocore.runtime;

import android.content.Context;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

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
    private static String protonNativeStatus(Context context) {
        Path receipt=context.getFilesDir().toPath().resolve(
            "offline-diagnostics/last-v49123-proton-native.json");
        try{
            if(Files.isSymbolicLink(receipt)
                ||!Files.isRegularFile(receipt,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(receipt)>16000)return "لم يُفحص تشغيل ملفات Proton بعد";
            JSONObject snapshot=new JSONObject(new String(
                Files.readAllBytes(receipt),StandardCharsets.UTF_8));
            String result=snapshot.optString("result","");
            if(result.contains("P11_LOADER=EXIT_0_")
                &&result.contains("P11_WINESERVER=EXIT_0_"))
                return "Wine وWineServer نجحا بفحص الإصدار فقط؛ تشغيل الألعاب غير مثبت";
            if(result.contains("P11_LOADER=")||result.contains("P11_ENGINE_STAGE="))
                return "فحص التشغيل لم ينجح أو لم يكتمل؛ راجع التشخيص العام";
        }catch(Exception ignored){}
        return "بانتظار فحص المحرك الفعلي على الجهاز";
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
                +"Proton 11 ARM64EC + FEX 2610: "
                +(KernixProtonFexInstallerV49121.staged(context)
                  ?"الحزمة الكاملة مثبتة؛ "+protonNativeStatus(context)
                  :"قيد التجهيز أو غير مثبتة") +"\n"
                +"X11 / Lorie: "+check(p.apkNativeLibs.resolve("libXlorie.so"))+"\n"
                +"Wine X11: "+check(p.apkNativeLibs.resolve("libwine_winex11.so"))+"\n"
                +"Vulkan Android: يحتاج اختبار GPU فعلي\n"
                +"DXVK: لم يُتحقق من تثبيته وربطه بالألعاب\n"
                +"VKD3D-Proton: لم يُتحقق من تثبيته وربطه بالألعاب\n"
                +"Mesa Turnip: لم يُتحقق من تثبيت تعريف بديل\n\n"
                +"الموجود لا يعني أنه اجتاز التشغيل على جهازك. "
                +"هذه شاشة جرد فقط، ولا تحمّل تعريفات من الإنترنت ولا تغيّر ملفات الألعاب.";
    }
}
