package com.rm11.autocore.runtime;

import java.util.ArrayDeque;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Isolates a real Wine assertion exception (0x80000101) from harmless
 * EXCEPTION_WINE_NAME_THREAD (0x406d1388), before a 14KiB rolling log tail
 * erases the interesting lines. Observational only: never alters Wine/FEX.
 */
public final class WineAssertionEvidence {
    private static final int BEFORE=22;
    private static final int AFTER=23;
    private static final int LINE_CAP=420;
    private static final int BLOCK_CAP=6700;
    private static final Pattern RIP=Pattern.compile(
            "trace:seh:dispatch_exception rip=([0-9a-fA-F]{5,16})");
    private final ArrayDeque<String> prior=new ArrayDeque<>();
    private final StringBuilder partial=new StringBuilder();
    private final StringBuilder first=new StringBuilder();
    private boolean seen;
    private int remaining;
    private String rip="UNKNOWN";
    private long readLines;
    private boolean logTruncated;
    private String assertionThread="UNKNOWN";

    public synchronized void accept(String data) {
        if(data==null)return;
        for(int i=0;i<data.length();i++) {
            char ch=data.charAt(i);
            if(ch=='\n') {
                process(partial.toString());
                partial.setLength(0);
                logTruncated=false;
            } else if(partial.length()<LINE_CAP)partial.append(ch);
            else logTruncated=true;
        }
    }
    private static void appendBounded(StringBuilder dest,String line) {
        if(dest.length()>=BLOCK_CAP)return;
        String clean=line.length()>LINE_CAP?line.substring(0,LINE_CAP):line;
        int available=BLOCK_CAP-dest.length();
        if(available>1)dest.append(clean,0,Math.min(clean.length(),available-1)).append('\n');
    }
    private static boolean isTrigger(String line) {
        return line.contains("dispatch_exception code=80000101")
                || line.contains("EXCEPTION_WINE_ASSERTION")
                || line.contains("wine: Assertion failed")
                || line.contains("Assertion failed at address")
                || line.contains("Assertion failed:");
    }
    private void process(String line) {
        readLines++;
        if(!seen && isTrigger(line)) {
            seen=true;
            int pos=line.indexOf(':');
            if(pos>0 && pos<=5)assertionThread=line.substring(0,pos);
            appendBounded(first,"WINE_ASSERTION_SOURCE_CONTEXT:");
            for(String prev:prior)appendBounded(first,prev);
            appendBounded(first,line);
            remaining=AFTER;
        }else if(remaining>0) {
            appendBounded(first,line);
            remaining--;
        }
        if(seen && "UNKNOWN".equals(rip)) {
            Matcher matcher=RIP.matcher(line);
            if(matcher.find())rip=matcher.group(1).toLowerCase(Locale.ROOT);
        }
        if(logTruncated && seen && remaining>0)
            appendBounded(first,"RM11_V463_LINE_TRUNCATED_FOR_PRIVACY");
        prior.addLast(line);
        while(prior.size()>BEFORE)prior.removeFirst();
    }
    public synchronized String pcHex(){return rip;}
    public synchronized String snapshot() {
        return "RM11_V463_WINE_ASSERTION_EVIDENCE\n"
                +"RM11_V463_ASSERTION_CODE=0x80000101\n"
                +"RM11_V463_ASSERTION_SEEN="+seen+"\n"
                +"RM11_V463_ASSERTION_THREAD="+assertionThread+"\n"
                +"RM11_V463_ASSERTION_RIP="+rip+"\n"
                +"RM11_V463_LINES_OBSERVED="+readLines+"\n"
                +"RM11_V463_ASSERTION_CONTEXT:\n"
                +(seen?first.toString():"No 0x80000101 assertion captured in this process.\n");
    }
}
