package com.rm11.autocore;
import android.view.KeyEvent;
import org.junit.Test;
import static org.junit.Assert.*;
public final class RM11ControllerBindingsV49041Test {
    @Test public void carxBindingsHaveKnownThrottleAndSteering(){
        String exe="/sdcard/Games/CarX Street/CarX Street.exe";
        assertTrue(RM11ControllerBindingsV49041.isCarX(exe));
        assertEquals(KeyEvent.KEYCODE_W,
            RM11ControllerBindingsV49041.defaultKey(exe,"RT",0));
        assertEquals(KeyEvent.KEYCODE_A,
            RM11ControllerBindingsV49041.defaultKey(exe,"LLEFT",0));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(exe,
            "DUP",KeyEvent.KEYCODE_W));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(exe,
            "DDOWN",KeyEvent.KEYCODE_S));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(exe,
            "DLEFT",KeyEvent.KEYCODE_A));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(exe,
            "DRIGHT",KeyEvent.KEYCODE_D));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(exe,
            "B",KeyEvent.KEYCODE_ESCAPE));
        assertEquals(KeyEvent.KEYCODE_ESCAPE,
            RM11ControllerBindingsV49041.defaultKey(exe,"START",0));
        assertEquals(0,
            RM11ControllerBindingsV49041.defaultKey(exe,"LUP",KeyEvent.KEYCODE_W));
        assertEquals(0,
            RM11ControllerBindingsV49041.defaultKey(exe,"Y",KeyEvent.KEYCODE_SHIFT_LEFT));
    }
    @Test public void unrelatedGamesKeepTheirOwnKeyboardDefaults(){
        assertFalse(RM11ControllerBindingsV49041.isCarX("/sdcard/Games/CarX Street/other.exe"));
        assertEquals(KeyEvent.KEYCODE_E,
            RM11ControllerBindingsV49041.defaultKey("Racing.exe","RB",KeyEvent.KEYCODE_E));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(
            "Racing.exe","B",KeyEvent.KEYCODE_ESCAPE));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(
            "Racing.exe","DUP",KeyEvent.KEYCODE_W));
        assertEquals(0,RM11ControllerBindingsV49041.defaultKey(
            "Racing.exe","DDOWN",KeyEvent.KEYCODE_S));
        assertEquals(KeyEvent.KEYCODE_ENTER,
            RM11ControllerBindingsV49041.defaultKey("Racing.exe","A",KeyEvent.KEYCODE_ENTER));
    }
}
