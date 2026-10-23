package com.rm11.autocore.runtime;

import java.util.ArrayDeque;
import java.util.Locale;

/** Retains bounded terminal Wine exception evidence before the journal's
 * 11-KB front-cap. No claims that a given exit code proves an X11 failure.
 * Does not mutate Wine or inspect source-game folders.
 */
public final class WineCrashEvidence {
    private WineCrashEvidence() {}

    public static String summarize(String boundedWineOutput, int code, boolean exited) {
        String log=boundedWineOutput==null?"":boundedWineOutput;
        StringBuilder out=new StringBuilder("RM11_GUI_FATAL_EVIDENCE_V285\n")
                .append("Client exit: ")
                .append(exited ? Integer.toString(code) : "TIMEOUT_NOT_EXITED")
                .append('\n');
        out.append("Windows MessageBox v284 entry marker: ")
                .append(log.contains("RM11_V284_MESSAGEBOXW_CALL_BEGIN")?"CAPTURED":"NOT_CAPTURED")
                .append('\n')
                .append("Windows MessageBox v284 return marker: ")
                .append(log.contains("RM11_V284_MESSAGEBOXW_RETURNED")?"CAPTURED":"NOT_CAPTURED")
                .append('\n');
        out.append("Wineboot missing wine.inf warning: ")
                .append(log.contains("wine.inf not found")?"OBSERVED":"NOT_IN_BOUNDED_CAPTURE").append('\n');
        out.append("Wine Win32 USER32 load trace: ")
                .append(log.toLowerCase(Locale.ROOT).contains("user32.dll")?"FOUND":"NOT_IN_BOUNDED_CAPTURE").append('\n');
        out.append("Native winex11.so initialization: NOT_DIRECTLY_PROVEN\n");

        ArrayDeque<String> lines=new ArrayDeque<>();
        int matches=0;
        for (String line : log.split("\\r?\\n")) {
            String lower=line.toLowerCase(Locale.ROOT);
            if (lower.contains("err:")
                    || lower.contains("warn:seh:")
                    || lower.contains("exception")
                    || lower.contains("uncaught")
                    || lower.contains("unhandled")
                    || lower.contains("0xc000")
                    || lower.contains("c0000005")
                    || lower.contains("wine.inf not found")
                    || lower.contains("winex11")
                    || lower.contains("x11drv")
                    || lower.contains("cannot open display")
                    || lower.contains("failed to open display")
                    || lower.contains("rm11_v284_")
                    || lower.contains("segmentation fault")
                    || lower.contains("fatal")) {
                matches++;
                String clipped=line.length()>240 ? line.substring(0,240)+" [CLIPPED]" : line;
                lines.addLast(clipped);
                if(lines.size()>16)lines.removeFirst();
            }
        }
        out.append("Total relevant log lines (bounded capture only): ").append(matches).append('\n');
        out.append("Last 16 relevant log lines:\n");
        if(lines.isEmpty())out.append("NO_MATCHES_IN_BOUNDED_CAPTURE\n");
        while(!lines.isEmpty())out.append(lines.removeFirst()).append('\n');
        // Last bytes often contain the exact signal/SEH error hidden by an
        // early journal cutoff, so store them separately ahead of full trace.
        int start=Math.max(0,log.length()-900);
        out.append("Terminal Wine log excerpt:\n")
                .append(log.substring(start)).append('\n');
        if(log.length()>=32768)
            out.append("Bounded log exceeded 32768 chars; absence is not evidence of no failure\n");
        return out.toString();
    }
}
