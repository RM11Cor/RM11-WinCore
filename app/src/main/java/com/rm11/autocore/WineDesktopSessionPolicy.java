package com.rm11.autocore;

/**
 * RM11 desktop lifetime belongs to the foreground Activity and Wine IPC
 * server, NOT to the bootstrap helper process.
 *
 * Wine's explorer.exe /desktop startup may return exit 0 after spawning
 * child components. It is therefore normal for the Java Process handle
 * to stop while the X11 windows and winefile remain registered with the
 * same wineserver. Do not destroy the desktop on that normal exit.
 */
public final class WineDesktopSessionPolicy {
    public enum Decision { KEEP_RUNNING, CLOSE_REQUESTED, SERVER_STOPPED }
    private WineDesktopSessionPolicy() { }

    public static Decision decide(boolean activityClosed, boolean serverAlive,
                                  boolean explorerAlive, boolean fileManagerAlive) {
        if(activityClosed) return Decision.CLOSE_REQUESTED;
        if(!serverAlive) return Decision.SERVER_STOPPED;
        // Helper process liveness must not terminate a Wine server session.
        // The X11 window or child Win32 process can outlive both helpers.
        return Decision.KEEP_RUNNING;
    }
}
