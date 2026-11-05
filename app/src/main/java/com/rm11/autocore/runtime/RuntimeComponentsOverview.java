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
        if(context==null)return "KERNIX_COMPONENT_AUDIT_NOT_AVAILABLE";
        return KernixComponentInventoryV49150.summary(context,null)
            +"\n\nهذا الجرد لا ينزل ملفات ولا يغيّر أي لعبة أو prefix.";
    }
}
