package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;
import static org.junit.Assert.*;

/** JNI never loads unless both signed native library and trusted font exist. */
public final class WineNativeFontProbeTest {
    @Test public void missingSignedLibraryIsSafeAndDoesNotStartWine() throws Exception {
        Path home=Files.createTempDirectory("rm11-v302-font-preflight");
        RuntimeLayout p=new RuntimeLayout(home.resolve("files"),home.resolve("native"));
        Files.createDirectories(p.appFiles);
        Files.createDirectories(p.apkNativeLibs);
        String out=WineNativeFontProbe.inspect(p);
        assertTrue(out,out.contains("SIGNED_FREETYPE_NOT_AVAILABLE"));
    }

    @Test public void invalidSignedElfIsRejectedBeforeAndroidJNI() throws Exception {
        Path home=Files.createTempDirectory("rm11-v302-font-small");
        RuntimeLayout p=new RuntimeLayout(home.resolve("files"),home.resolve("native"));
        Files.createDirectories(p.appFiles);
        Files.createDirectories(p.apkNativeLibs);
        Files.write(p.apkNativeLibs.resolve("librm11_freetype_core.so"),
                new byte[]{0x7f,0x45,0x4c,0x46});
        String out=WineNativeFontProbe.inspect(p);
        assertTrue(out,out.contains("SIGNED_FREETYPE_NOT_AVAILABLE"));
    }
}
