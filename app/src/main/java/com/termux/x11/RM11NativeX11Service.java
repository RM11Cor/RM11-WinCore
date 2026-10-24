package com.termux.x11;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import java.io.File;
import java.io.IOException;

/**
 * RM11 v4 in-package native X.Org service experiment.
 *
 * Uses the pinned Termux:X11 Lorie AAR, running in its OWN Android service
 * process (:rm11_xorg). The X.Org server may call exit/_exit: it must never
 * run inside the user's RM11 foreground Activity process.
 *
 * This is NOT active in the legacy RM11 v3 desktop and must only be enabled
 * after merging the AAR with BuildConfig.APPLICATION_ID set to RM11's app ID.
 * No Termux installation or root should be necessary for this design.
 */
public final class RM11NativeX11Service extends Service {
    public static final String TMPDIR_NAME="rm11-native-x11";
    public static final int DISPLAY=2;
    private static final String TAG="RM11-Xorg";
    private boolean launched;

    @Override public void onCreate() {
        super.onCreate();
        // Android's normal Service main thread already owns a prepared Looper,
        // required by CmdEntryPoint's static Handler initialization.
    }

    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(launched)return START_STICKY;
        try {
            File tmp=new File(getFilesDir(),TMPDIR_NAME);
            if(!tmp.isDirectory() && !tmp.mkdirs())
                throw new IllegalStateException("RM11_V4_CANNOT_CREATE_PRIVATE_XORG_TMPDIR");
            // Termux X.Org's pinned Xtrans patch uses this for the Unix socket
            // path: $TMPDIR/.X11-unix/X2; same UID as the RM11 app process.
            Os.setenv("TMPDIR",tmp.getCanonicalPath(),true);
            Os.setenv("XDG_RUNTIME_DIR",tmp.getCanonicalPath(),true);
            CmdEntryPoint.ctx=getApplicationContext();
            // The regular Termux shell-loader is deliberately not used here.
            // Load the native library shipped in RM11's own signed APK.
            System.loadLibrary("Xlorie");
            launched=true;
            // The X.Org native implementation runs its server thread and
            // manages its own event loop. Never invoke CmdEntryPoint.main(),
            // which would start a second Looper.loop() in a Service process.
            new CmdEntryPoint(new String[]{":"+DISPLAY,"-ac","-nolisten","tcp"});
            Log.i(TAG,"RM11_V4_NATIVE_XORG_START_REQUESTED display=:"+DISPLAY);
            return START_STICKY;
        } catch(UnsatisfiedLinkError | IOException | ErrnoException |
                RuntimeException e) {
            launched=false;
            Log.e(TAG,"RM11_V4_NATIVE_XORG_START_FAILED",e);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public void onDestroy() {
        // Native server is owned by this separate process; a live X server
        // cannot be safely aborted by destroying its Java Service instance.
        // Complete lifecycle control is required before production adoption.
        Log.i(TAG,"RM11_V4_NATIVE_XORG_SERVICE_DESTROYED");
        super.onDestroy();
    }
}
