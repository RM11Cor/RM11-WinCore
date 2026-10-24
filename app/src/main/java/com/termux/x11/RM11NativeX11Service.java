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
    private CmdEntryPoint entry;

    @Override public void onCreate() {
        super.onCreate();
        // Android's normal Service main thread already owns a prepared Looper,
        // required by CmdEntryPoint's static Handler initialization.
    }

    private synchronized boolean ensureStarted() {
        if(launched && entry!=null)return true;
        try {
            File tmp=new File(getFilesDir(),TMPDIR_NAME);
            if(!tmp.isDirectory() && !tmp.mkdirs())
                throw new IllegalStateException("RM11_V4_CANNOT_CREATE_PRIVATE_XORG_TMPDIR");
            Os.setenv("TMPDIR",tmp.getCanonicalPath(),true);
            Os.setenv("XDG_RUNTIME_DIR",tmp.getCanonicalPath(),true);
            CmdEntryPoint.ctx=getApplicationContext();
            System.loadLibrary("Xlorie");
            // A Binder references the actual native X.Org command instance;
            // clients must wait for the Unix X socket before requesting frames.
            CmdEntryPoint started=new CmdEntryPoint(
                    new String[]{":"+DISPLAY,"-ac","-nolisten","tcp"});
            entry=started;
            launched=true;
            Log.i(TAG,"RM11_V4_NATIVE_XORG_START_REQUESTED display=:"+DISPLAY);
            return true;
        } catch(UnsatisfiedLinkError | IOException | ErrnoException |
                RuntimeException e) {
            launched=false;
            entry=null;
            Log.e(TAG,"RM11_V4_NATIVE_XORG_START_FAILED",e);
            return false;
        }
    }

    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(!ensureStarted())stopSelf(startId);
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        // Same-package binder to Lorie MainActivity, rather than solely
        // relying on a package ACTION_START broadcast from the X server.
        return ensureStarted()?entry:null;
    }

    @Override public void onDestroy() {
        // Native server is owned by this separate process; a live X server
        // cannot be safely aborted by destroying its Java Service instance.
        // Complete lifecycle control is required before production adoption.
        Log.i(TAG,"RM11_V4_NATIVE_XORG_SERVICE_DESTROYED");
        super.onDestroy();
        // Service is explicitly isolated in :rm11_xorg. Stop the native
        // long-lived X.Org pthread without touching the foreground RM11 process.
        android.os.Process.killProcess(android.os.Process.myPid());
    }
}
