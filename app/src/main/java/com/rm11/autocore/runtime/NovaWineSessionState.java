package com.rm11.autocore.runtime;

/**
 * Pure in-memory guard for a single Wine/X11 foreground session.
 * Once wineserver exits unexpectedly, attempts to launch EXEs stay blocked
 * until the user explicitly leaves and starts a NEW Wine activity.
 * The on-device prefix and game files are never modified.
 */
public final class NovaWineSessionState {
    private boolean winefileReady;
    private boolean serverCrashed;
    private int serverExitCode;

    public synchronized void markWinefileReady(boolean ready) {
        winefileReady=ready && !serverCrashed;
    }
    public synchronized void markServerCrashed(int exitCode) {
        serverCrashed=true;
        winefileReady=false;
        serverExitCode=exitCode;
    }
    public synchronized boolean canLaunchExe() {
        return winefileReady && !serverCrashed;
    }
    public synchronized boolean hasServerCrashed() {
        return serverCrashed;
    }
    public synchronized int serverExitCode() {
        return serverExitCode;
    }
    public synchronized String diagnostic() {
        return "RM11_V441_WINEFILE_READY="+winefileReady+"\n"
                +"RM11_V441_SERVER_CRASHED_THIS_SESSION="+serverCrashed+"\n"
                +"RM11_V441_SERVER_LAST_EXIT_CODE="+(serverCrashed
                    ?Integer.toString(serverExitCode):"NONE")+"\n"
                +"RM11_V441_DIRECT_EXE_ALLOWED="+canLaunchExe()+"\n";
    }
}
