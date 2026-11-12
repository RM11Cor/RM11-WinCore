package com.fh5.port;

/** Hard read-only limits for the second JNE discovered after the first shared CALL.
 * These labels are static graph states, never observed runtime outcomes.
 */
final class PostJoinBranch {
    private PostJoinBranch() { }
    static final int MAX_SUCCESSOR_PROBES = 2;
    static final int SAMPLE_BYTES_PER_SUCCESSOR = 128;
    static String classifyTarget(long target, long imageSize, long branchStart, long otherBranch) {
        if(!JumpJoin.inImage(target,imageSize))return "DIRECT_TARGET_UNRESOLVED_OR_OUT_OF_IMAGE";
        if(target==branchStart)return "STATIC_SELF_LOOP";
        if(otherBranch>0 && target==otherBranch)return "DUPLICATE_OTHER_SUCCESSOR";
        return "SAFE_DIRECT_IN_IMAGE_TARGET";
    }
    static String classifyPair(long taken,long fallthrough,long imageSize) {
        if(!JumpJoin.inImage(taken,imageSize) || !JumpJoin.inImage(fallthrough,imageSize))
            return "ONE_OR_BOTH_SUCCESSORS_UNRESOLVED";
        if(taken==fallthrough)return "SAME_DIRECT_SUCCESSOR";
        return "TWO_DISTINCT_STATIC_SUCCESSORS";
    }
}
