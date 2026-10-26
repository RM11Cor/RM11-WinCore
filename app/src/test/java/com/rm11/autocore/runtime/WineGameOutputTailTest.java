package com.rm11.autocore.runtime;

import org.junit.Test;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public final class WineGameOutputTailTest {
    @Test public void capturesLiveStdoutWithoutWaitingForProcessExit() throws Exception {
        AtomicReference<String> latest=new AtomicReference<>("");
        WineGameOutputTail.drain(new ByteArrayInputStream(
                "err:module:load_dll failed\n".getBytes(StandardCharsets.UTF_8)),
                latest::set);
        assertTrue(latest.get().contains("load_dll failed"));
    }
    @Test public void avoidsUnboundedDiagnosticMemory() {
        String value="";
        for(int i=0;i<40;i++)value=WineGameOutputTail.append(value,
                "E".repeat(1000));
        assertEquals(14000,value.length());
    }
    @Test public void nullInputsAreSafe() {
        assertEquals("",WineGameOutputTail.append(null,null));
    }
}
