package com.rm11.autocore;

import android.view.KeyEvent;
import org.junit.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.*;

public final class RM11GamepadDriveV49036Test {
    private static final class Recorder implements RM11GamepadDriveV49036.Sink {
        final List<String> events=new ArrayList<>();
        @Override public void key(int k,boolean down) {
            events.add(k+":"+(down?"DOWN":"UP"));
        }
        void event(int key,boolean down) {
            assertEquals(key+":"+(down?"DOWN":"UP"),
                         events.get(events.size()-1));
        }
    }
    @Test public void leftStickAndRightTriggerCanHoldSteeringAndGasSimultaneously(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        pad.axes(-0.8f,0f,0.9f,0f,0f,0f);
        assertEquals(2,r.events.size());
        assertTrue(r.events.contains(KeyEvent.KEYCODE_A+":DOWN"));
        assertTrue(r.events.contains(KeyEvent.KEYCODE_W+":DOWN"));
        pad.axes(-0.7f,0f,0.8f,0f,0f,0f);
        assertEquals(2,r.events.size()); // no spurious repeats
        pad.axes(0f,0f,0f,0f,0f,0f);
        assertEquals(4,r.events.size());
        assertTrue(r.events.contains(KeyEvent.KEYCODE_A+":UP"));
        assertTrue(r.events.contains(KeyEvent.KEYCODE_W+":UP"));
    }
    @Test public void deadzoneUsesHysteresis(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        pad.axes(0.29f,0f,0f,0f,0f,0f);
        assertEquals(0,r.events.size());
        pad.axes(0.44f,0f,0f,0f,0f,0f);
        r.event(KeyEvent.KEYCODE_D,true);
        pad.axes(0.25f,0f,0f,0f,0f,0f);
        assertEquals(1,r.events.size());
        pad.axes(0.12f,0f,0f,0f,0f,0f);
        r.event(KeyEvent.KEYCODE_D,false);
        assertEquals(2,r.events.size());
    }
    @Test public void faceButtonAndTriggerShareThrottleWithoutEarlyRelease(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        pad.axes(0f,0f,0.9f,0f,0f,0f);
        pad.button(KeyEvent.KEYCODE_BUTTON_A,true);
        assertEquals(1,r.events.size());
        pad.axes(0f,0f,0f,0f,0f,0f);
        assertEquals(1,r.events.size());
        pad.button(KeyEvent.KEYCODE_BUTTON_A,false);
        assertEquals(2,r.events.size());
        r.event(KeyEvent.KEYCODE_W,false);
    }
    @Test public void gasAndBrakeCanUseDpadPlusTwoButtons(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        pad.button(KeyEvent.KEYCODE_DPAD_UP,true);
        pad.button(KeyEvent.KEYCODE_BUTTON_R2,true);
        assertEquals(1,r.events.size());
        pad.button(KeyEvent.KEYCODE_DPAD_UP,false);
        assertEquals(1,r.events.size());
        pad.button(KeyEvent.KEYCODE_BUTTON_R2,false);
        r.event(KeyEvent.KEYCODE_W,false);
    }
    @Test public void releaseAllNeverLeavesHeldInputs(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        pad.button(KeyEvent.KEYCODE_BUTTON_X,true);
        pad.axes(-1f,0f,1f,0f,0f,0f);
        assertEquals(3,r.events.size());
        pad.releaseAll();
        assertEquals(6,r.events.size());
        pad.releaseAll();
        assertEquals(6,r.events.size());
    }
    @Test public void physicalInputsUseSelectedGameKeyboardBindings(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r,(control,def)->{
            if(control.equals("RT"))return KeyEvent.KEYCODE_SPACE;
            if(control.equals("A"))return KeyEvent.KEYCODE_ENTER;
            if(control.equals("LLEFT"))return KeyEvent.KEYCODE_J;
            return def;
        });
        pad.axes(-0.9f,0f,0.8f,0f,0f,0f);
        assertTrue(r.events.contains(KeyEvent.KEYCODE_J+":DOWN"));
        assertTrue(r.events.contains(KeyEvent.KEYCODE_SPACE+":DOWN"));
        pad.button(KeyEvent.KEYCODE_BUTTON_A,true);
        assertTrue(r.events.contains(KeyEvent.KEYCODE_ENTER+":DOWN"));
        pad.releaseAll();
        assertTrue(r.events.contains(KeyEvent.KEYCODE_J+":UP"));
        assertTrue(r.events.contains(KeyEvent.KEYCODE_SPACE+":UP"));
        assertTrue(r.events.contains(KeyEvent.KEYCODE_ENTER+":UP"));
    }
    @Test public void collidingAndroidKeycodesCannotPrematurelyReleaseSameBoundKey(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r,
            (control,def)->KeyEvent.KEYCODE_W);
        // DPAD_UP=19 and BUTTON_X=99 have the same low four bits.
        pad.button(KeyEvent.KEYCODE_DPAD_UP,true);
        pad.button(KeyEvent.KEYCODE_BUTTON_X,true);
        assertEquals(1,r.events.size());
        pad.button(KeyEvent.KEYCODE_DPAD_UP,false);
        assertEquals(1,r.events.size());
        pad.button(KeyEvent.KEYCODE_BUTTON_X,false);
        assertEquals(2,r.events.size());
        r.event(KeyEvent.KEYCODE_W,false);
    }
    @Test public void disabledGameBindingSendsNoKeyboardCodeZero(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r,
            (control,def)->control.equals("A")?0:def);
        pad.button(KeyEvent.KEYCODE_BUTTON_A,true);
        pad.button(KeyEvent.KEYCODE_BUTTON_A,false);
        assertEquals(0,r.events.size());
    }
    @Test public void ignoresUnrecognizedKeysAndNonFiniteAnalog(){
        Recorder r=new Recorder();
        RM11GamepadDriveV49036 pad=new RM11GamepadDriveV49036(r);
        assertFalse(RM11GamepadDriveV49036.supportsButton(KeyEvent.KEYCODE_VOLUME_UP));
        assertTrue(RM11GamepadDriveV49036.supportsButton(KeyEvent.KEYCODE_BUTTON_START));
        pad.button(KeyEvent.KEYCODE_VOLUME_UP,true);
        pad.axes(Float.NaN,Float.POSITIVE_INFINITY,0f,0f,0f,0f);
        assertEquals(0,r.events.size());
        pad.button(KeyEvent.KEYCODE_BUTTON_START,true);
        pad.button(KeyEvent.KEYCODE_BUTTON_START,false);
        assertEquals(2,r.events.size());
        r.event(KeyEvent.KEYCODE_ESCAPE,false);
    }
}
