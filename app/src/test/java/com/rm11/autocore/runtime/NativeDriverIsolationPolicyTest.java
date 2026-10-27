package com.rm11.autocore.runtime;

import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public final class NativeDriverIsolationPolicyTest {
    private static final String SEH="{\"timeUnixMs\":1793074139832,"
        +"\"test\":\"v462-first-seh-final\","
        +"\"result\":\"RM11_V462_SEH_FATAL_EVENT_SEEN=true\\n"
        +"Unhandled exception: page fault on read access to 0x0000000000000070 in 64-bit code\"}";
    private static final String V467="{\"timeUnixMs\":1793074135503,"
        +"\"test\":\"v467-silksong-off-retest\","
        +"\"result\":\"RM11_V467_VULKAN_FALLBACK=OFF\\n"
        +"RM11_V467_CONSUMED_MARKER_WRITTEN=true\"}";

    @Test public void v467AlreadyConsumedButV468PermitsOneNewGameOnlyRetest() throws Exception {
        Path dir=Files.createTempDirectory("rm11-v468-retest");
        Files.write(dir.resolve("last-game-seh.json"),SEH.getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("last-v467-isolation.json"),V467.getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("v467-silksong-off-retest-consumed.txt"),
                "1793074135503".getBytes(StandardCharsets.UTF_8));
        NativeDriverIsolationPolicy.Decision first=
            NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe");
        assertTrue(first.reason,first.isolate);
        assertTrue(NativeDriverIsolationPolicy.commitOnce(dir,first));
        assertFalse(NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe").isolate);
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(SEH,null,"other-game.exe"));
    }

    @Test public void rejectUnrelatedOrUnconfirmedFaults() throws Exception {
        Path dir=Files.createTempDirectory("rm11-v468-missing");
        Files.write(dir.resolve("last-game-seh.json"),SEH.getBytes(StandardCharsets.UTF_8));
        assertFalse(NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe").isolate);
        Files.write(dir.resolve("last-v467-isolation.json"),V467.getBytes(StandardCharsets.UTF_8));
        assertTrue(NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe").isolate);
        Files.write(dir.resolve("last-game-seh.json"),
            SEH.replace("0x0000000000000070","0x0000000000000080").getBytes(StandardCharsets.UTF_8));
        assertFalse(NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe").isolate);
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(SEH,"already-used",
            "Hollow Knight Silksong.exe"));
    }
}
