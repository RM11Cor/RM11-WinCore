package com.rm11.autocore;

import android.view.KeyEvent;
import java.util.Locale;

/** Per-game keyboard compatibility defaults, distinct from real Xbox XInput. */
public final class RM11ControllerBindingsV49041 {
    private RM11ControllerBindingsV49041(){}
    public static boolean isCarX(String path){
        if(path==null)return false;
        return path.replace('\\','/').toLowerCase(Locale.ROOT).endsWith("/carx street.exe");
    }
    public static String profileName(String path){
        return isCarX(path)?"CARX_STREET_KEYBOARD":"GENERIC_XBOX_AUTO";
    }
    public static int defaultKey(String path,String control,int generic){
        if(!isCarX(path))return generic;
        switch(control){
            // CarX keyboard: A/D steer, W throttle, S brake, Space handbrake.
            case "LLEFT":return KeyEvent.KEYCODE_A;
            case "LRIGHT":return KeyEvent.KEYCODE_D;
            case "LUP":case "LDOWN":return 0;
            case "RT":return KeyEvent.KEYCODE_W;
            case "LT":return KeyEvent.KEYCODE_S;
            case "X":return KeyEvent.KEYCODE_SPACE;
            case "A":return KeyEvent.KEYCODE_ENTER;
            case "B":case "START":return KeyEvent.KEYCODE_ESCAPE;
            case "BACK":return KeyEvent.KEYCODE_TAB;
            case "DUP":return KeyEvent.KEYCODE_DPAD_UP;
            case "DDOWN":return KeyEvent.KEYCODE_DPAD_DOWN;
            case "DLEFT":return KeyEvent.KEYCODE_DPAD_LEFT;
            case "DRIGHT":return KeyEvent.KEYCODE_DPAD_RIGHT;
            // Unknown mappings must not trigger unrelated game actions.
            case "Y":case "LB":case "RB":case "L3":case "R3":
            case "RUP":case "RDOWN":case "RLEFT":case "RRIGHT":return 0;
            default:return generic;
        }
    }
}
