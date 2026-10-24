package com.rm11.autocore;

/**
 * An unexpected Wine IPC server exit may be recovered once per foreground
 * desktop lifetime, never after the user leaves the Activity. This isolates
 * a broken X11/IPC session without deleting user data or looping forever.
 */
public final class WineDesktopRecoveryPolicy {
    private WineDesktopRecoveryPolicy() {}

    public static boolean mayRestartAfterServerDeath(boolean activityClosed,
                                                     int completedAttempts) {
        return !activityClosed && completedAttempts == 1;
    }
}
