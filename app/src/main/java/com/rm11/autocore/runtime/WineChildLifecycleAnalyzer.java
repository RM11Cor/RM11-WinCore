package com.rm11.autocore.runtime;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Correlate Wineboot's creation thread ID with its own NT exit request. */
public final class WineChildLifecycleAnalyzer {
    private static final Pattern CREATED=Pattern.compile(
            "NtCreateUserProcess[^\\r\\n]*wineboot\\.exe[^\\r\\n]*\\bpid\\s+([0-9a-fA-F]{4})\\s+tid\\s+([0-9a-fA-F]{4})",
            Pattern.CASE_INSENSITIVE);
    private WineChildLifecycleAnalyzer() {}

    public static String report(String log) {
        if (log==null) return "WINEBOOT_CHILD_EXIT: NO_LOG\n";
        Matcher child=CREATED.matcher(log);
        if(!child.find()) return "WINEBOOT_CHILD_EXIT: CREATION_NOT_CAPTURED\n";
        String tid=child.group(2);
        Pattern exit=Pattern.compile(
                "(?m)^"+Pattern.quote(tid)+
                ":trace:process:NtTerminateProcess handle 0x0, exit_code ([0-9]+), process_exiting 0\\.");
        Matcher observed=exit.matcher(log);
        if(!observed.find()) return "WINEBOOT_CHILD_EXIT: NOT_OBSERVED\n";
        String code=observed.group(1);
        return "WINEBOOT_CHILD_EXIT: NT_TERMINATION_REQUEST_CAPTURED\n"
                +"Wineboot exit code requested: "+code+"\n"
                +"Wineboot NT exit-zero observed: "+("0".equals(code)?"YES":"NO")+"\n"
                +"Full independent Android child waitpid: NOT VERIFIED\n";
    }
}
