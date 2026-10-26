package com.rm11.autocore.diagnostics;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.*;

public final class DiagnosticJournalBudgetTest {
    @Test public void largeOldJournalMustNotResetToJustNewEvent() {
        List<String> events=new ArrayList<>();
        for(int i=0;i<100;i++)
            events.add("{\"test\":\"ordinary-"+i+"\",\"result\":\""
                    +"x".repeat(4800)+"\"}");
        events.add("{\"test\":\"v463-assertion-final\",\"result\":\"ASSERTION\"}");
        String compact=DiagnosticJournalBudget.lastCompleteEvents(events,31000,18);
        assertTrue(compact.contains("v463-assertion-final"));
        assertTrue(compact.contains("ordinary-"));
        assertTrue(compact.getBytes(StandardCharsets.UTF_8).length<=31000);
        assertTrue(compact.startsWith("[")&&compact.endsWith("]"));
    }
    @Test public void preserveUtf8WholeRecordsAndSkipSingleOversizedRecord() {
        String big="{\"test\":\"big\",\"result\":\""+ "y".repeat(30000)+"\"}";
        String crash="{\"test\":\"SEH\",\"result\":\"خطأ في المكدس\"}";
        String result=DiagnosticJournalBudget.lastCompleteEvents(
                List.of(big,crash),250,18);
        assertFalse(result.contains("big"));
        assertTrue(result.contains("SEH"));
        assertTrue(result.getBytes(StandardCharsets.UTF_8).length<=250);
    }
}
