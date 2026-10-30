package com.rm11.autocore;

/** Pure, allocation-free two-channel correction. Both axes in one stick pair
 *  are swapped together; buttons and D-pad are never remapped. */
public final class RM11ControllerAxisOrderV49058 {
    private RM11ControllerAxisOrderV49058(){}
    public static float first(boolean swap,float first,float second) {
        return swap?second:first;
    }
    public static float second(boolean swap,float first,float second) {
        return swap?first:second;
    }
}
