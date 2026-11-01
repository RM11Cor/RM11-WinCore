package com.rm11.autocore.runtime;

/** RC325 host-freeze quarantine policy.
 * The app must not execute a potentially GPU/CPU locking native X11 test
 * after the user reports an Android-wide stall. Every path entering the
 * native session Activity can start X.Org, even direct-game mode. Quarantine
 * ALL of them until independent safety proof exists, while leaving the
 * launcher library and offline export accessible. Never delete user data.
 * This is not a claim that the root cause is known.
 */
public final class KernixHostFreezeSafetyV49151 {
    private KernixHostFreezeSafetyV49151() {}
    /** Temporary fail-closed release policy; must be lifted by a separately
     * reviewed change after proving host safety without real-device stalls. */
    public static boolean blockAnyNativeX11Session() {
        return true;
    }
    public static boolean blockUnqualifiedX11Diagnostics(
            boolean protonX11WindowProbe,boolean x11WsiOrSurfaceProbe) {
        return protonX11WindowProbe || x11WsiOrSurfaceProbe;
    }
}
