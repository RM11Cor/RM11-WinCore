package com.rm11.autocore;

import android.view.KeyEvent;
import java.util.HashMap;
import java.util.Map;

/**
 * CarX Street Android external controller -> Wine keyboard state mapper.
 * Dedicated to the selected game. This does not emulate or claim native
 * XInput/DirectInput, which require a separate authenticated driver bridge.
 *
 * Analog input is thresholded to a *digital* held key. Separate source bits
 * make combined stick+trigger+face+Dpad safe and prevent one source from
 * releasing a key still held by another source.
 */
public final class RM11GamepadDriveV49036 {
    public interface Sink { void key(int androidKeyCode,boolean pressed); }

    private static final int STICK=1,TRIGGER=2,HAT=4,BUTTON=8;
    private static final float PRESS=0.38f,RELEASE=0.18f;
    private final Sink sink;
    private final Map<Integer,Integer> held=new HashMap<>();

    public RM11GamepadDriveV49036(Sink sink){
        if(sink==null)throw new IllegalArgumentException("Sink missing");
        this.sink=sink;
    }

    private boolean has(int key,int source) {
        Integer mask=held.get(key);
        return mask!=null && (mask & source)!=0;
    }
    private void set(int key,int source,boolean pressed) {
        int before=held.containsKey(key)?held.get(key):0;
        int after=pressed?(before|source):(before&~source);
        if(before==after)return;
        if(after==0)held.remove(key);else held.put(key,after);
        if((before==0)!=(after==0))sink.key(key,after!=0);
    }
    private void analog(int key,int source,float amount){
        if(Float.isNaN(amount) || Float.isInfinite(amount))amount=0f;
        boolean pressed=has(key,source)?amount>RELEASE:amount>PRESS;
        set(key,source,pressed);
    }
    private static float clamp(float v) {
        if(Float.isNaN(v)||Float.isInfinite(v))return 0f;
        return Math.max(-1f,Math.min(1f,v));
    }
    /**
     * x/y left stick; RT throttle and LT brake; hatX/hatY controller Dpad
     * (for devices delivering Dpad only as analog HAT axes).
     * CarX PC defaults: W gas, S brake, A left, D right, Space handbrake.
     */
    public void axes(float x,float y,float rt,float lt,float hatX,float hatY){
        x=clamp(x);y=clamp(y);
        hatX=clamp(hatX);hatY=clamp(hatY);
        analog(KeyEvent.KEYCODE_A,STICK,-x);
        analog(KeyEvent.KEYCODE_D,STICK,x);
        analog(KeyEvent.KEYCODE_W,STICK,-y);
        analog(KeyEvent.KEYCODE_S,STICK,y);
        analog(KeyEvent.KEYCODE_W,TRIGGER,Math.max(0f,clamp(rt)));
        analog(KeyEvent.KEYCODE_S,TRIGGER,Math.max(0f,clamp(lt)));
        analog(KeyEvent.KEYCODE_A,HAT,-hatX);
        analog(KeyEvent.KEYCODE_D,HAT,hatX);
        analog(KeyEvent.KEYCODE_W,HAT,-hatY);
        analog(KeyEvent.KEYCODE_S,HAT,hatY);
    }

    public static boolean supportsButton(int button) {
        switch(button) {
            case KeyEvent.KEYCODE_DPAD_LEFT:
            case KeyEvent.KEYCODE_DPAD_RIGHT:
            case KeyEvent.KEYCODE_DPAD_UP:
            case KeyEvent.KEYCODE_DPAD_DOWN:
            case KeyEvent.KEYCODE_BUTTON_A:
            case KeyEvent.KEYCODE_BUTTON_B:
            case KeyEvent.KEYCODE_BUTTON_X:
            case KeyEvent.KEYCODE_BUTTON_L1:
            case KeyEvent.KEYCODE_BUTTON_R1:
            case KeyEvent.KEYCODE_BUTTON_L2:
            case KeyEvent.KEYCODE_BUTTON_R2:
            case KeyEvent.KEYCODE_BUTTON_START:
                return true;
            default:return false;
        }
    }
    public void button(int button,boolean pressed) {
        int key;
        switch(button){
            case KeyEvent.KEYCODE_DPAD_LEFT:key=KeyEvent.KEYCODE_A;break;
            case KeyEvent.KEYCODE_DPAD_RIGHT:key=KeyEvent.KEYCODE_D;break;
            case KeyEvent.KEYCODE_DPAD_UP:
            case KeyEvent.KEYCODE_BUTTON_A:
            case KeyEvent.KEYCODE_BUTTON_R1:
            case KeyEvent.KEYCODE_BUTTON_R2:key=KeyEvent.KEYCODE_W;break;
            case KeyEvent.KEYCODE_DPAD_DOWN:
            case KeyEvent.KEYCODE_BUTTON_B:
            case KeyEvent.KEYCODE_BUTTON_L1:
            case KeyEvent.KEYCODE_BUTTON_L2:key=KeyEvent.KEYCODE_S;break;
            case KeyEvent.KEYCODE_BUTTON_X:key=KeyEvent.KEYCODE_SPACE;break;
            case KeyEvent.KEYCODE_BUTTON_START:key=KeyEvent.KEYCODE_ESCAPE;break;
            default:return;
        }
        // Any two physical buttons mapped to the same key should not
        // release each other. Allocate distinct source bit per button.
        int source=1 << (8+(button&15));
        set(key,source,pressed);
    }
    public void releaseAll() {
        Map<Integer,Integer> snapshot=new HashMap<>(held);
        held.clear();
        for(Integer key:snapshot.keySet())sink.key(key,false);
    }
}
