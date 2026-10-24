package com.rm11.autocore;

/**
 * A deliberately narrow first-attempt-only bridge from verified Android
 * FreeType glyph rendering into the Wine file-manager GUI process.
 *
 * Wine IPC server / Explorer bootstraps never inherit this opt-in.
 * The original Wine desktop is restarted WITHOUT the font hook at most once
 * after an unexpected server death or immediate nonzero Winefile exit.
 */
public final class WineDesktopFontLaunchPolicy {
    private WineDesktopFontLaunchPolicy() {}

    public static boolean enableForWinefile(boolean fontProbeSucceeded,
                                             boolean activityClosed,
                                             int attemptNumber) {
        return fontProbeSucceeded && !activityClosed && attemptNumber == 1;
    }

    public static boolean retryAfterEarlyWinefileFailure(boolean activityClosed,
                                                         int attemptNumber,
                                                         int code,
                                                         long elapsedMs) {
        return !activityClosed && attemptNumber == 1 && code != 0
                && elapsedMs >= 0 && elapsedMs < 15000;
    }
}
