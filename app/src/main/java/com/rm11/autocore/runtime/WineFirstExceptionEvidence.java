package com.rm11.autocore.runtime;

import java.util.ArrayDeque;

/**
 * Bounded streaming capture of the FIRST Wine SEH exception and FIRST
 * invalid/unhandled stack frame. Long +seh/+unwind logs can overwrite a
 * 14 KiB tail and the 11 KiB offline journal. This class retains critical
 * evidence while draining Wine stdout with no unbounded memory growth.
 *
 * It never modifies the exception, stack, thread or game process.
 */
public final class WineFirstExceptionEvidence {
    private static final int CONTEXT_LINES=9;
    private static final int FOLLOW_LINES=12;
    private static final int MAX_LINE=500;
    private static final int MAX_BLOCK=3400;
    private final ArrayDeque<String> recent=new ArrayDeque<>();
    private final StringBuilder partial=new StringBuilder();
    private final StringBuilder first=new StringBuilder();
    private final StringBuilder fatal=new StringBuilder();
    private int firstRemaining;
    private int fatalRemaining;
    private long lineCount;
    private boolean firstSeen;
    private boolean fatalSeen;
    private String fatalPc="";

    public synchronized void accept(String chunk) {
        if(chunk==null||chunk.isEmpty())return;
        for(int i=0;i<chunk.length();i++) {
            char ch=chunk.charAt(i);
            if(ch=='\n') {
                capture(partial.toString());
                partial.setLength(0);
            }else if(partial.length()<MAX_LINE) {
                // Wine messages may contain arbitrarily long path or trace
                // data: cap each line; still drain the entire pipe.
                partial.append(ch);
            }
        }
    }
    private static void add(StringBuilder out,String line) {
        if(out.length()>=MAX_BLOCK)return;
        String s=line.length()>MAX_LINE?line.substring(0,MAX_LINE):line;
        int remaining=MAX_BLOCK-out.length();
        if(remaining>1)out.append(s,0,Math.min(s.length(),remaining-1)).append('\n');
    }
    private static boolean isException(String l) {
        return l.contains("trace:seh:dispatch_exception code=")
                || l.contains("warn:seh:dispatch_exception backtrace:")
                || l.contains("Unhandled exception:");
    }
    private static boolean isFatal(String l) {
        return l.contains("call_seh_handlers invalid frame")
                || l.contains("Exception frame is not in stack limits")
                || l.contains("Unhandled exception:");
    }
    private void capture(String line) {
        lineCount++;
        if(!firstSeen && isException(line)) {
            firstSeen=true;
            add(first,"FIRST_WINE_SEH_EVENT:");
            for(String old:recent)add(first,old);
            add(first,line);
            firstRemaining=FOLLOW_LINES;
        } else if(firstRemaining>0) {
            add(first,line);
            firstRemaining--;
        }
        if(line.contains("Unhandled exception:")) {
            int at=line.lastIndexOf("(0x");
            if(at>=0) {
                int end=line.indexOf(')',at+3);
                if(end>at+3) {
                    String pc=line.substring(at+3,end);
                    if(pc.matches("[0-9a-fA-F]{8,16}"))fatalPc=pc;
                }
            }
        }
        if(!fatalSeen && isFatal(line)) {
            fatalSeen=true;
            add(fatal,"FIRST_INVALID_OR_UNHANDLED_FRAME:");
            for(String old:recent)add(fatal,old);
            add(fatal,line);
            fatalRemaining=FOLLOW_LINES;
        } else if(fatalRemaining>0) {
            add(fatal,line);
            fatalRemaining--;
        }
        recent.addLast(line);
        while(recent.size()>CONTEXT_LINES)recent.removeFirst();
    }
    public synchronized String fatalPcHex(){return fatalPc;}
    public synchronized String snapshot() {
        // Finite-size output always puts the decisive indicators first.
        StringBuilder report=new StringBuilder();
        report.append("RM11_V462_FIRST_SEH_CAPTURE\n")
              .append("RM11_V462_SEH_FIRST_EVENT_SEEN=").append(firstSeen).append('\n')
              .append("RM11_V462_SEH_FATAL_EVENT_SEEN=").append(fatalSeen).append('\n')
              .append("RM11_V462_SEH_LINES_READ=").append(lineCount).append('\n')
              .append("RM11_V468_FATAL_PC=").append(fatalPc.isEmpty()?"UNKNOWN":fatalPc).append('\n')
              .append("RM11_V462_FIRST_EXCEPTION_CONTEXT:\n")
              .append(firstSeen?first:"(none observed in bounded output)\n")
              .append("RM11_V462_FIRST_INVALID_FRAME_CONTEXT:\n")
              .append(fatalSeen?fatal:"(none observed in bounded output)\n");
        return report.toString();
    }
}
