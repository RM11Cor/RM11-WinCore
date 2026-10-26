package com.rm11.autocore.runtime;

/** Distinguish an actual Win64 SEH handler return from a mere Wine process
 * launch. Neither compiler success nor GUI X11 health indicates SEH success. */
public final class SehProbeVerdict {
    private SehProbeVerdict(){}
    public static boolean passed(boolean finished,int exit,String output) {
        return finished && exit==0 && output!=null
            && output.contains("RM11_V460_SEH_PROBE_STARTED=x64")
            && output.contains("RM11_V460_SEH_HANDLER_REACHED=YES")
            && output.contains("RM11_V460_SEH_PROBE_PASS=YES")
            && !output.contains("Exception frame is not in stack limits")
            && !output.contains("call_seh_handlers invalid frame");
    }
}
