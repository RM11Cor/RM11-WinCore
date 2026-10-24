package com.rm11.autocore;

import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineDesktopLogCaptureTest {
    private static void put(WineDesktopLogCapture c,String s) {
        byte[] data=s.getBytes(StandardCharsets.UTF_8);
        c.append(data,0,data.length);
    }
    @Test public void shortWineLogUnchanged() {
        WineDesktopLogCapture c=new WineDesktopLogCapture();
        put(c,"RM11_V304_READY\n");
        assertEquals("RM11_V304_READY\n",c.snapshot());
    }
    @Test public void longWineTraceKeepsLatestFailure() {
        WineDesktopLogCapture c=new WineDesktopLogCapture();
        put(c,"RM11_V304_WINE_BOOT_BEGIN\n");
        byte[] noise=new byte[50000];
        java.util.Arrays.fill(noise,(byte)'x');
        c.append(noise,0,noise.length);
        put(c,"\nwinefile:err:filemanager EXIT=2\n");
        String log=c.snapshot();
        assertTrue(log,log.startsWith("RM11_V304_WINE_BOOT_BEGIN"));
        assertTrue(log,log.contains("[RM11_V304_LOG_MIDDLE_OMITTED"));
        assertTrue(log,log.endsWith("winefile:err:filemanager EXIT=2\n"));
        assertTrue(log.length()<20000);
    }
    @Test public void splittingIntoChunksPreservesTailAndOrdering() {
        WineDesktopLogCapture c=new WineDesktopLogCapture();
        byte[] b=new byte[24000];
        for(int i=0;i<b.length;i++)b[i]=(byte)('A'+i%26);
        for(int i=0;i<b.length;i+=733)
            c.append(b,i,Math.min(733,b.length-i));
        String log=c.snapshot();
        assertTrue(log,log.endsWith(new String(b,b.length-400,400,
                StandardCharsets.UTF_8)));
    }
    @Test public void invalidSliceFailsClosed() {
        WineDesktopLogCapture c=new WineDesktopLogCapture();
        try { c.append(new byte[2],1,3); fail("bounds"); }
        catch(IllegalArgumentException expected) { }
    }
}
