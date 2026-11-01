package com.rm11.autocore.runtime;

/** The Android exit reason labels are not diagnoses of a whole-device hang. */
public final class KernixHostFreezeExitReasonV49152 {
    private KernixHostFreezeExitReasonV49152(){}
    public static String classify(int reason){
        switch(reason){
            case 2: return "APP_PROCESS_SIGNALED_CAUSE_UNDETERMINED";
            case 3: return "APP_PROCESS_REPORTED_LOW_MEMORY_NOT_SYSTEM_FREEZE_PROOF";
            case 4: return "APP_PROCESS_JAVA_CRASH_NOT_SYSTEM_FREEZE_PROOF";
            case 5: return "APP_PROCESS_NATIVE_CRASH_NOT_SYSTEM_FREEZE_PROOF";
            case 6: return "APP_PROCESS_ANR_NOT_SYSTEM_FREEZE_PROOF";
            case 1: return "APP_PROCESS_SELF_EXIT";
            default: return "APP_PROCESS_EXIT_REASON_UNCLASSIFIED";
        }
    }
}
