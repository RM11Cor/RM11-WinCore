package com.rm11.autocore.runtime;

import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public final class NativeDriverIsolationPolicyTest {
    private static final String LOG="{\"timeUnixMs\":1793044580645,"
        +"\"test\":\"v465-native-abort-final\","
        +"\"result\":\"RM11_V465_NATIVE_ABORT_CALLER_SEEN=true\\n"
        +"RM11_V465_NATIVE_ABORT_CALLER_IMAGE=libllvm-glnext.so\\n"
        +"RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET=0x6eb10\\n\"}";

    @Test public void onlySilksongAndOnlyOncePerRealDeviceEvidence() throws Exception {
        Path dir=Files.createTempDirectory("rm11-v466-test");
        Files.writeString(dir.resolve("last-native-abort.json"),LOG,StandardCharsets.UTF_8);
        NativeDriverIsolationPolicy.Decision first=
                NativeDriverIsolationPolicy.evaluate(dir,"Hollow Knight Silksong.exe");
        assertTrue(first.isolate);
        assertEquals("1793044580645",first.sourceTimestamp);
        assertTrue(NativeDriverIsolationPolicy.commitOnce(dir,first));
        assertFalse(NativeDriverIsolationPolicy.evaluate(dir,
                "Hollow Knight Silksong.exe").isolate);
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(LOG,null,
                "unrelated-game.exe"));
        assertTrue(NativeDriverIsolationPolicy.shouldIsolate(
                LOG,"1793044580644","Hollow Knight Silksong.exe"));
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(
                LOG,"1793044580645","Hollow Knight Silksong.exe"));
    }

    @Test public void willNotTouchUnprovenCrashes() throws Exception {
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(
                "{\"timeUnixMs\":1793044580645,\"result\":\"other abort\"}",
                null,"Hollow Knight Silksong.exe"));
        assertFalse(NativeDriverIsolationPolicy.shouldIsolate(
                LOG.replace("libllvm-glnext.so","libnotadreno.so"),
                null,"Hollow Knight Silksong.exe"));
        assertFalse(NativeDriverIsolationPolicy.evaluate(
                Files.createTempDirectory("rm11-v466-empty"),
                "Hollow Knight Silksong.exe").isolate);
    }
}
