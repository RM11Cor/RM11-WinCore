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
        if(ctx==null)return "KERNIX_COMPONENT_AUDIT_NOT_AVAILABLE";
        return KernixComponentInventoryV49150.summary(ctx,exe)
            +"\n\nالإعداد الحالي للعبة:\n"
            +R4ManualComponentsV49069.summary(ctx,exe)
            +"\nهذه الاقتراحات لا تغيّر ملفات اللعبة أو إعداداتها المحفوظة.";
    }
}
