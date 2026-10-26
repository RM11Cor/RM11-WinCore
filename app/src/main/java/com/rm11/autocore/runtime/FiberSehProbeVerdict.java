package com.rm11.autocore.runtime;

/** Must observe the x64 fiber switch, SEH handler and process exit. */
public final class FiberSehProbeVerdict {
    private FiberSehProbeVerdict(){}
    public static boolean passed(boolean exited,int code,String log) {
        return exited && code==0 && log!=null
                && log.contains("RM11_V461_FIBER_PROBE_STARTED=x64")
                && log.contains("RM11_V461_FIBER_SWITCH_ENTERED=YES")
                && log.contains("RM11_V461_FIBER_SEH_HANDLER_REACHED=YES")
                && log.contains("RM11_V461_FIBER_SEH_PASS=YES")
                && !log.contains("Exception frame is not in stack limits")
                && !log.contains("call_seh_handlers invalid frame");
    }
}
