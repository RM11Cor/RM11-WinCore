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
    /** Optional per-game bindings. The legacy CarX constructor keeps its original keys. */
    public interface BindingResolver { int resolve(String control,int defaultKey); }

    private static final int STICK=1,TRIGGER=2,HAT=4,BUTTON=8;
    private static final float PRESS=0.38f,RELEASE=0.18f;
    private final Sink sink;
    private final BindingResolver bindings;
    private final Map<Integer,Integer> held=new HashMap<>();

    public RM11GamepadDriveV49036(Sink sink){
        this(sink,(control,defaultKey)->defaultKey);
    }
    public RM11GamepadDriveV49036(Sink sink,BindingResolver bindings){
        if(sink==null||bindings==null)throw new IllegalArgumentException("Sink or bindings missing");
        this.sink=sink;
        this.bindings=bindings;
    }
    private int bind(String control,int defaultKey){
        return bindings.resolve(control,defaultKey);
    }

    private boolean has(int key,int source) {
        Integer mask=held.get(key);
        return mask!=null && (mask & source)!=0;
    }
    private void set(int key,int source,boolean pressed) {
        if(key==0)return; // A per-game binding may deliberately disable an action.
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
        analog(bind("LLEFT",KeyEvent.KEYCODE_A),STICK,-x);
        analog(bind("LRIGHT",KeyEvent.KEYCODE_D),STICK,x);
        analog(bind("LUP",KeyEvent.KEYCODE_W),STICK,-y);
        analog(bind("LDOWN",KeyEvent.KEYCODE_S),STICK,y);
        analog(bind("RT",KeyEvent.KEYCODE_W),TRIGGER,Math.max(0f,clamp(rt)));
        analog(bind("LT",KeyEvent.KEYCODE_S),TRIGGER,Math.max(0f,clamp(lt)));
        analog(bind("DLEFT",KeyEvent.KEYCODE_A),HAT,-hatX);
        analog(bind("DRIGHT",KeyEvent.KEYCODE_D),HAT,hatX);
        analog(bind("DUP",KeyEvent.KEYCODE_W),HAT,-hatY);
        analog(bind("DDOWN",KeyEvent.KEYCODE_S),HAT,hatY);
    }

    /** Stable distinct sources: Android keycodes modulo 16 collide (e.g. X and Dpad Up). */
    private static int buttonIndex(int button){
        switch(button) {
            case KeyEvent.KEYCODE_DPAD_LEFT:return 0;
            case KeyEvent.KEYCODE_DPAD_RIGHT:return 1;
            case KeyEvent.KEYCODE_DPAD_UP:return 2;
            case KeyEvent.KEYCODE_DPAD_DOWN:return 3;
            case KeyEvent.KEYCODE_BUTTON_A:return 4;
            case KeyEvent.KEYCODE_BUTTON_B:return 5;
            case KeyEvent.KEYCODE_BUTTON_X:return 6;
            case KeyEvent.KEYCODE_BUTTON_Y:return 7;
            case KeyEvent.KEYCODE_BUTTON_L1:return 8;
            case KeyEvent.KEYCODE_BUTTON_R1:return 9;
            case KeyEvent.KEYCODE_BUTTON_L2:return 10;
            case KeyEvent.KEYCODE_BUTTON_R2:return 11;
            case KeyEvent.KEYCODE_BUTTON_START:return 12;
            case KeyEvent.KEYCODE_BUTTON_SELECT:return 13;
            case KeyEvent.KEYCODE_BUTTON_THUMBL:return 14;
            case KeyEvent.KEYCODE_BUTTON_THUMBR:return 15;
            default:return -1;
        }
    }
    public static boolean supportsButton(int button) {
        return buttonIndex(button)>=0;
    }
    public void button(int button,boolean pressed) {
        int key; String action;
        switch(button){
            case KeyEvent.KEYCODE_DPAD_LEFT:action="DLEFT";key=KeyEvent.KEYCODE_A;break;
            case KeyEvent.KEYCODE_DPAD_RIGHT:action="DRIGHT";key=KeyEvent.KEYCODE_D;break;
            case KeyEvent.KEYCODE_DPAD_UP:action="DUP";key=KeyEvent.KEYCODE_W;break;
            case KeyEvent.KEYCODE_DPAD_DOWN:action="DDOWN";key=KeyEvent.KEYCODE_S;break;
            case KeyEvent.KEYCODE_BUTTON_A:action="A";key=KeyEvent.KEYCODE_W;break;
            case KeyEvent.KEYCODE_BUTTON_B:action="B";key=KeyEvent.KEYCODE_S;break;
            case KeyEvent.KEYCODE_BUTTON_X:action="X";key=KeyEvent.KEYCODE_SPACE;break;
            case KeyEvent.KEYCODE_BUTTON_Y:action="Y";key=KeyEvent.KEYCODE_SHIFT_LEFT;break;
            case KeyEvent.KEYCODE_BUTTON_L1:action="LB";key=KeyEvent.KEYCODE_S;break;
            case KeyEvent.KEYCODE_BUTTON_R1:action="RB";key=KeyEvent.KEYCODE_W;break;
            case KeyEvent.KEYCODE_BUTTON_L2:action="LT";key=KeyEvent.KEYCODE_S;break;
            case KeyEvent.KEYCODE_BUTTON_R2:action="RT";key=KeyEvent.KEYCODE_W;break;
            case KeyEvent.KEYCODE_BUTTON_START:action="START";key=KeyEvent.KEYCODE_ESCAPE;break;
            case KeyEvent.KEYCODE_BUTTON_SELECT:action="BACK";key=KeyEvent.KEYCODE_TAB;break;
            case KeyEvent.KEYCODE_BUTTON_THUMBL:action="L3";key=KeyEvent.KEYCODE_CTRL_LEFT;break;
            case KeyEvent.KEYCODE_BUTTON_THUMBR:action="R3";key=KeyEvent.KEYCODE_C;break;
            default:return;
        }
        // Each physical button gets a distinct bit even when the user binds
        // two buttons to the same keyboard key (no premature KEY_UP).
        int source=1 << (8+buttonIndex(button));
        set(bind(action,key),source,pressed);
    }
    public void releaseAll() {
        Map<Integer,Integer> snapshot=new HashMap<>(held);
        held.clear();
        for(Integer key:snapshot.keySet())sink.key(key,false);
    }
}
