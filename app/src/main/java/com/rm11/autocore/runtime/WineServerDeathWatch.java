package com.rm11.autocore.runtime;

import java.util.concurrent.TimeUnit;

/**
 * Watch a selected GUI process and its co-owned Wine IPC server together.
 *
 * Unlike waitFor(45, SECONDS), a hung client may never exit after the
 * server aborts: without an explicit server-death signal the fallback
 * path cannot activate. Bounded polling exits quickly on actual server
 * process death; it is NOT a server-health probe or a crash detector
 * when a different wineserver instance is being used.
 */
public final class WineServerDeathWatch {
    public enum Outcome { CLIENT_EXITED, SERVER_EXITED, TIMEOUT }
    private WineServerDeathWatch() {}

    public static Outcome await(Process client, Process server, long timeoutMs)
            throws InterruptedException {
        if(client==null || server==null || timeoutMs<=0 || timeoutMs>60000)
            throw new IllegalArgumentException("invalid bounded Wine watch");
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while(true) {
            // The server check comes FIRST: if both have stopped, preserve
            // server-crash evidence and qualify for the safety fallback.
            if(!server.isAlive()) return Outcome.SERVER_EXITED;
            if(!client.isAlive()) return Outcome.CLIENT_EXITED;
            long remaining=deadline-System.nanoTime();
            if(remaining<=0) return Outcome.TIMEOUT;
            long step=Math.max(1,Math.min(250,
                    TimeUnit.NANOSECONDS.toMillis(remaining)));
            if(client.waitFor(step,TimeUnit.MILLISECONDS)) {
                return server.isAlive()?Outcome.CLIENT_EXITED:Outcome.SERVER_EXITED;
            }
        }
    }
}
