package com.rm11.autocore;

import android.view.KeyEvent;
import java.util.Locale;

/** Per-game keyboard compatibility defaults, distinct from real Xbox XInput.
 *  v49043: never fake the native Xbox B / D-pad using Esc / arrow keys.
 */
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
        // Across all games, no controller's B/D-pad should silently map to
        // Esc or arrow keys: these have unpredictable per-game meanings.
        // Users may assign keyboard fallbacks explicitly in control settings.
        if("B".equals(control) || "DUP".equals(control)
                || "DDOWN".equals(control) || "DLEFT".equals(control)
                || "DRIGHT".equals(control))return 0;
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
            // An Xbox B or D-pad is NOT a keyboard Esc/arrow. CarX treated
            // these synthetic keyboard arrows as throttle/brake. Until the
            // Windows controller enumerates natively, do not invent actions.
            case "B":return 0;
            case "START":return KeyEvent.KEYCODE_ESCAPE;
            case "BACK":return KeyEvent.KEYCODE_TAB;
            case "DUP":case "DDOWN":case "DLEFT":case "DRIGHT":return 0;
            // Unknown mappings must not trigger unrelated game actions.
            case "Y":case "LB":case "RB":case "L3":case "R3":
            case "RUP":case "RDOWN":case "RLEFT":case "RRIGHT":return 0;
            default:return generic;
        }
    }
}
