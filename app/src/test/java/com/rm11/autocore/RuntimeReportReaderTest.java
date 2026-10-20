package com.rm11.autocore;
import org.junit.Test;
import static org.junit.Assert.*;
public final class RuntimeReportReaderTest {
    @Test public void parsesEveryResultOnce() {
        StringBuilder raw=new StringBuilder("RM11-WinCore v2.4.13 Windows ten-check diagnostic\n");
        for(int i=1;i<=10;i++) {
            raw.append(String.format(java.util.Locale.ROOT,"[%02d/10] ",i));
            raw.append(i==9||i==10?"NOT_CONFIGURED":"PASS").append(" — case\n");
        }
        RuntimeReportReader.Result r=RuntimeReportReader.read(raw.toString());
        assertEquals(8,r.passed);
        assertEquals(0,r.failed);
        assertEquals(2,r.notConfigured);
    }
    @Test(expected=IllegalArgumentException.class) public void rejectsIncomplete() {
        RuntimeReportReader.read("RM11-WinCore v2.4.13 Windows ten-check diagnostic\n[01/10] PASS — case");
    }
}
