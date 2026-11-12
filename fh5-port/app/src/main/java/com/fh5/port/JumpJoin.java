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
    static final class GraphResult {
        final String status;
        final long joinRva;
        final boolean cycleDetected;
        private GraphResult(String status,long joinRva,boolean cycleDetected) {
            this.status=status;
            this.joinRva=joinRva;
            this.cycleDetected=cycleDetected;
        }
    }
    /**
     * Compare edges of two statically discovered JCC successor paths:
     *   taken -> takenNext, notTaken -> notTakenNext.
     * Returning to the OTHER branch's node is reconvergence, not by itself
     * a loop. Two mutually returning edges are a cycle and not a safe join.
     */
    static GraphResult classifyGraph(long taken,long notTaken,
                                    long takenNext,long notTakenNext,
                                    long imageSize) {
        if(!inImage(taken,imageSize) || !inImage(notTaken,imageSize))
            return new GraphResult("BRANCH_START_UNRESOLVED",-1,false);
        boolean tKnown=inImage(takenNext,imageSize);
        boolean nKnown=inImage(notTakenNext,imageSize);
        if(taken==notTaken)
            return new GraphResult("SAME_JCC_SUCCESSOR",taken,false);
        if((tKnown && takenNext==taken) ||
           (nKnown && notTakenNext==notTaken) ||
           (tKnown && nKnown && takenNext==notTaken && notTakenNext==taken))
            return new GraphResult("STATIC_CYCLE_DETECTED",-1,true);
        if(nKnown && notTakenNext==taken)
            return new GraphResult("RECONVERGENCE_AT_TAKEN_BRANCH",taken,false);
        if(tKnown && takenNext==notTaken)
            return new GraphResult("RECONVERGENCE_AT_NOT_TAKEN_BRANCH",notTaken,false);
        if(tKnown && nKnown && takenNext==notTakenNext)
            return new GraphResult("RECONVERGENCE_AT_SHARED_NEXT_TARGET",takenNext,false);
        if(!tKnown || !nKnown)
            return new GraphResult("SECOND_HOP_UNRESOLVED",-1,false);
        return new GraphResult("DISTINCT_SECOND_HOP_TARGETS",-1,false);
    }

    static boolean previouslyVisited(long next,long taken,long notTaken,long call) {
        return next==taken || next==notTaken || next==call;
    }
}
