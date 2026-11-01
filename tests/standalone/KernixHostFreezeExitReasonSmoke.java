package com.rm11.autocore.runtime;
public final class KernixHostFreezeExitReasonSmoke {
    private static void assertEqual(String expected,String got){
        if(!expected.equals(got))throw new AssertionError(expected+" != "+got);
    }
    public static void main(String[] args){
        assertEqual("APP_PROCESS_SIGNALED_CAUSE_UNDETERMINED",
                KernixHostFreezeExitReasonV49152.classify(2));
        assertEqual("APP_PROCESS_REPORTED_LOW_MEMORY_NOT_SYSTEM_FREEZE_PROOF",
                KernixHostFreezeExitReasonV49152.classify(3));
        assertEqual("APP_PROCESS_NATIVE_CRASH_NOT_SYSTEM_FREEZE_PROOF",
                KernixHostFreezeExitReasonV49152.classify(5));
        assertEqual("APP_PROCESS_ANR_NOT_SYSTEM_FREEZE_PROOF",
                KernixHostFreezeExitReasonV49152.classify(6));
        assertEqual("APP_PROCESS_EXIT_REASON_UNCLASSIFIED",
                KernixHostFreezeExitReasonV49152.classify(0));
        System.out.println("KERNIX_HOST_FREEZE_PASSIVE_EXIT_CLASSIFICATION_PASS");
    }
}
