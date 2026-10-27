package com.rm11.autocore.runtime;

/** A single, top-level, input-output, fullscreen-sized, non-redirected
 * UNMAPPED window is the only eligible target. Never map the X11 root,
 * cursor, tray, helper dialogs, or multiple ambiguous candidates. */
public final class X11HiddenWindowRecoveryPolicyV483 {
    private X11HiddenWindowRecoveryPolicyV483(){}

    public static boolean isCandidate(int windowClass,int mapState,
            boolean overrideRedirect,int width,int height,int rootW,int rootH) {
        return windowClass==1 && mapState==0 && !overrideRedirect
            && rootW>=640 && rootH>=360
            && width>0 && height>0
            && (long)width*3 >= (long)rootW*2
            && (long)height*3 >= (long)rootH*2
            && width<=rootW+80 && height<=rootH+80;
    }
}
