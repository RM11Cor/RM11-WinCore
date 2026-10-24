package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/** Regression for the device v2.9.9 45-second hang after Wine IPC death. */
public final class WineServerDeathWatchTest {
    private static Process command(String script) throws IOException {
        return new ProcessBuilder("/bin/sh","-c",script).start();
    }
    @Test public void detectsServerDeathBeforeHungClientTimesOut() throws Exception {
        Process client=command("sleep 20");
        Process server=command("exit 1");
        try {
            long start=System.nanoTime();
            assertEquals(WineServerDeathWatch.Outcome.SERVER_EXITED,
                    WineServerDeathWatch.await(client,server,6000));
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<3000);
            assertTrue(client.isAlive());
        } finally {
            client.destroyForcibly();
            server.destroyForcibly();
        }
    }
    @Test public void capturesNormalClientCompletionWithLivingServer() throws Exception {
        Process client=command("exit 48");
        Process server=command("sleep 20");
        try {
            assertEquals(WineServerDeathWatch.Outcome.CLIENT_EXITED,
                    WineServerDeathWatch.await(client,server,3000));
            assertEquals(48,client.exitValue());
        } finally {
            client.destroyForcibly();
            server.destroyForcibly();
        }
    }
    @Test public void timeoutWhenBothStillRunning() throws Exception {
        Process client=command("sleep 20");
        Process server=command("sleep 20");
        try {
            assertEquals(WineServerDeathWatch.Outcome.TIMEOUT,
                    WineServerDeathWatch.await(client,server,100));
            assertTrue(client.isAlive());
            assertTrue(server.isAlive());
        } finally {
            client.destroyForcibly();
            server.destroyForcibly();
        }
    }
    @Test public void rejectsUnboundedWait() throws Exception {
        Process client=command("exit 0");
        Process server=command("exit 0");
        try {
            try {
                WineServerDeathWatch.await(client,server,60001);
                fail("Unbounded Wine session watch should fail closed");
            } catch (IllegalArgumentException expected) { }
            try {
                WineServerDeathWatch.await(client,server,0);
                fail("Zero timeout cannot watch");
            } catch (IllegalArgumentException expected) { }
        } finally {
            client.destroyForcibly();
            server.destroyForcibly();
        }
    }
}