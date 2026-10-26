package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public final class NovaFontProbePolicyTest {
    @Test public void probeNameIsStrictButCaseInsensitive(){
        assertTrue(NovaFontProbePolicy.isTestName("RM11-Win64-Visible-GUI-Test.exe"));
        assertTrue(NovaFontProbePolicy.isTestName("rm11-win64-visible-gui-test.EXE"));
        assertFalse(NovaFontProbePolicy.isTestName("Game.exe"));
        assertFalse(NovaFontProbePolicy.isTestName("RM11-Win64-Visible-GUI-Test.exe.bak"));
    }
    @Test public void pinnedHashRejectsOtherExecutables(){
        assertTrue(NovaFontProbePolicy.matchesKnownDigest(NovaFontProbePolicy.TEST_SHA256));
        assertFalse(NovaFontProbePolicy.matchesKnownDigest("0".repeat(64)));
    }
    @Test public void nameAndLengthRejectBeforeTouchingNativeRuntime() throws Exception {
        Path folder=Files.createTempDirectory("rm11-font-probe-");
        try{
            Path unrelated=folder.resolve("game.exe");
            Files.write(unrelated,new byte[4096]);
            try{
                NovaFontProbePolicy.requireKnownSignedProbe(unrelated,null);
                fail("game could opt into signed FreeType experiment");
            }catch(java.io.IOException expected){
                assertTrue(expected.getMessage().contains("ONLY_FOR_VERIFIED"));
            }
            Path shortProbe=folder.resolve(NovaFontProbePolicy.TEST_NAME);
            Files.write(shortProbe,new byte[1024]);
            try{
                NovaFontProbePolicy.requireKnownSignedProbe(shortProbe,null);
                fail("short or corrupt GUI probe admitted");
            }catch(java.io.IOException expected){
                assertTrue(expected.getMessage().contains("ONLY_FOR_VERIFIED"));
            }
        }finally{
            try(java.util.stream.Stream<Path> paths=Files.walk(folder)){
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(p->{
                    try{Files.deleteIfExists(p);}catch(java.io.IOException ignored){}
                });
            }
        }
    }
}
