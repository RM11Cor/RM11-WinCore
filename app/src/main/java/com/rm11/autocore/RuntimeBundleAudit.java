package com.rm11.autocore;

import android.content.Context;
import java.io.InputStream;

/** Header-level APK inventory only; full verification happens at extraction. */
public final class RuntimeBundleAudit {
    private RuntimeBundleAudit() {}

    public static String describe(Context context) {
        try (InputStream in = context.getAssets().open("runtime/rm11-wine-stack.zip")) {
            int a = in.read(), b = in.read(), c = in.read(), d = in.read();
            boolean zip = a == 0x50 && b == 0x4b && c == 0x03 && d == 0x04;
            if (!zip) return "Runtime ZIP: bad header";
            return "RM11 v2.4.17: Wine + FEX ZIP found in APK\n"
                    + "Archive header: PASS (not full integrity)\n"
                    + "Press Wine smoke test to provision and attempt actual --version\n"
                    + "EXE / DXVK / Turnip: NOT VERIFIED";
        } catch (Exception e) {
            return "Runtime bundle not found: " + e.getClass().getSimpleName();
        }
    }
}
