package com.rm11.autocore;

/** Pure controller UI policy, testable without Android or game sessions. */
public final class RM11ControllerVisibilityV49042 {
    private RM11ControllerVisibilityV49042(){}
    public static boolean shouldShowTouch(boolean manualVisible,boolean physicalConnected){
        return manualVisible && !physicalConnected;
    }
}
