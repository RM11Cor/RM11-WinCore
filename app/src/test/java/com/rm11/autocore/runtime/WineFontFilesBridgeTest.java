package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public final class WineFontFilesBridgeTest {
    private RuntimeLayout createLayout() throws Exception {
        Path tmp=Files.createTempDirectory("rm11-wine-fonts-v298");
        RuntimeLayout p=new RuntimeLayout(tmp.resolve("files"),tmp.resolve("native"));
        Files.createDirectories(p.wineShare.resolve("wine/fonts"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/Fonts"));
        for(String font:new String[]{"tahoma.ttf","tahomabd.ttf"}) {
            byte[] ttf=new byte[11000];
            ttf[0]=0;ttf[1]=1;ttf[2]=0;ttf[3]=0;
            Files.write(p.wineShare.resolve("wine/fonts").resolve(font),ttf);
        }
        return p;
    }
    @Test public void linksBundledWineTahomaWithoutOverwriteOrRepeat() throws Exception {
        RuntimeLayout p=createLayout();
        String first=WineFontFilesBridge.prepare(p);
        assertTrue(first,first.contains("tahoma.ttf: READY_NEW_TRUSTED_LINK"));
        assertTrue(first,first.contains("tahomabd.ttf: READY_NEW_TRUSTED_LINK"));
        Path font=p.winePrefix.resolve("drive_c/windows/Fonts/tahoma.ttf");
        assertTrue(Files.isSymbolicLink(font));
        assertEquals(p.wineShare.resolve("wine/fonts/tahoma.ttf").toRealPath(),font.toRealPath());
        String second=WineFontFilesBridge.prepare(p);
        assertTrue(second,second.contains("tahoma.ttf: EXISTING_TRUSTED_LINK"));
        Files.delete(font);
        byte[] protectedData={7,4,8};
        Files.write(font,protectedData);
        String third=WineFontFilesBridge.prepare(p);
        assertTrue(third,third.contains("tahoma.ttf: EXISTING_FILE_PRESERVED"));
        assertArrayEquals(protectedData,Files.readAllBytes(font));
    }
    @Test public void refusesMissingSourceWithoutCreatingAnything() throws Exception {
        RuntimeLayout p=createLayout();
        Files.delete(p.wineShare.resolve("wine/fonts/tahoma.ttf"));
        String output=WineFontFilesBridge.prepare(p);
        assertTrue(output,output.contains("tahoma.ttf: NO_TRUSTED_BUNDLED_FONT"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/Fonts/tahoma.ttf")));
    }
}
