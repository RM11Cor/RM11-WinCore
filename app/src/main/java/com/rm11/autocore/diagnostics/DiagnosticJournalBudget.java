package com.rm11.autocore.diagnostics;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;

/** Pure-Java journal cap: keep complete JSON objects, never clear the
 * preceding events only because compact or pretty JSON crossed a threshold.
 * The caller must supply already validated, sanitized JSONObject.toString()
 * payloads. This class does not interpret or modify user source content. */
public final class DiagnosticJournalBudget {
    public static final int MAX_STORED_BYTES=135000;
    public static final int MAX_EVENTS=18;
    private DiagnosticJournalBudget() {}

    public static String lastCompleteEvents(List<String> objects) {
        return lastCompleteEvents(objects,MAX_STORED_BYTES,MAX_EVENTS);
    }
    static String lastCompleteEvents(List<String> objects,int maxBytes,int maxEvents) {
        if(objects==null||maxBytes<2||maxEvents<1)return "[]";
        ArrayDeque<String> kept=new ArrayDeque<>();
        int used=2; // JSON array brackets
        for(int i=objects.size()-1;i>=0;i--) {
            String obj=objects.get(i);
            if(obj==null||obj.isEmpty())continue;
            int bytes=obj.getBytes(StandardCharsets.UTF_8).length;
            if(bytes+3>maxBytes)continue; // skip oversized records individually
            if(used+bytes+(kept.isEmpty()?0:1)>maxBytes
                    ||kept.size()>=maxEvents)break;
            kept.addFirst(obj);
            used+=bytes+(kept.size()==1?0:1);
        }
        StringBuilder out=new StringBuilder(used+32).append('[');
        boolean comma=false;
        for(String obj:kept) {
            if(comma)out.append(',');
            out.append(obj);
            comma=true;
        }
        return out.append(']').toString();
    }
}
