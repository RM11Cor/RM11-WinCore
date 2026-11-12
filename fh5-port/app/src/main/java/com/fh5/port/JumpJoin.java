package com.fh5.port;

/**
 * Pure, conservative static graph comparison; NO runtime branch conditions,
 * CPU emulation, Windows process, or original game execution.
 */
final class JumpJoin {
    private JumpJoin() { }

    static boolean inImage(long rva,long imageSize) {
        return rva>0 && imageSize>0 && rva<imageSize;
    }
    static String classify(long taken,long notTaken,long imageSize) {
        if(!inImage(taken,imageSize) || !inImage(notTaken,imageSize))
            return "ONE_OR_BOTH_UNRESOLVED";
        if(taken==notTaken)
            return "SAME_IMMEDIATE_JMP_DESTINATION";
        return "DISTINCT_IMMEDIATE_JMP_DESTINATIONS";
    }
    static boolean previouslyVisited(long next,long taken,long notTaken,long call) {
        return next==taken || next==notTaken || next==call;
    }
}
