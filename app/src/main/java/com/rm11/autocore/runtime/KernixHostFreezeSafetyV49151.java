package com.rm11.autocore.runtime;

/** RC325 host-freeze quarantine policy.
 * The app must not execute a potentially GPU/CPU locking native X11 test
 * after the user reports an Android-wide stall. This quarantine is ONLY
 * for laboratory X11/GDI/WSI diagnostics, never file/data deletion and
 * never a claim that the renderer/root-cause is known.
 */
public final class KernixHostFreezeSafetyV49151 {
    private KernixHostFreezeSafetyV49151() {}
    public static boolean blockUnqualifiedX11Diagnostics(
            boolean protonX11WindowProbe,boolean x11WsiOrSurfaceProbe) {
        return protonX11WindowProbe || x11WsiOrSurfaceProbe;
    }
}
