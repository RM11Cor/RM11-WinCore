package com.termux.x11;

import android.os.IBinder;

/**
 * Bind the app-owned native X.Org Service to the authentic LorieView screen.
 * Direct binder delivery is intentionally independent of Termux's implicit
 * ACTION_START broadcast (whose behavior can vary across Android versions).
 *
 * Called only after the private X11 Unix socket exists, avoiding an early
 * getXConnection() before the native X.Org main loop is initialized.
 */
public final class RM11NativeDisplayConnector {
    private RM11NativeDisplayConnector() {}

    public static boolean connectIfNeeded(MainActivity screen, IBinder binder) {
        if(screen == null || binder == null || !binder.isBinderAlive()
                || screen.getLorieView() == null) return false;
        if(!screen.getLorieView().connected())
            screen.connectToService(binder);
        return screen.getLorieView().connected();
    }
}
