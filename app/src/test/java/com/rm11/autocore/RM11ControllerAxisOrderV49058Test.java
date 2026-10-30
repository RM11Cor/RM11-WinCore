package com.rm11.autocore;
import org.junit.Test;
import static org.junit.Assert.*;

public class RM11ControllerAxisOrderV49058Test {
    @Test public void identityDoesNotAlterDefaultXboxAxes() {
        assertEquals(-0.75f,RM11ControllerAxisOrderV49058.first(false,-0.75f,0.2f),0f);
        assertEquals(0.2f,RM11ControllerAxisOrderV49058.second(false,-0.75f,0.2f),0f);
    }
    @Test public void leftRightStickChannelsSwapAsFullPairs() {
        float lx=0.75f,ly=-0.6f,rx=-0.2f,ry=0.8f;
        assertEquals(rx,RM11ControllerAxisOrderV49058.first(true,lx,rx),0f);
        assertEquals(ry,RM11ControllerAxisOrderV49058.first(true,ly,ry),0f);
        assertEquals(lx,RM11ControllerAxisOrderV49058.second(true,lx,rx),0f);
        assertEquals(ly,RM11ControllerAxisOrderV49058.second(true,ly,ry),0f);
    }
    @Test public void throttleBrakeRemainIndependentAnalogChannels() {
        float brake=0.33f,gas=0.91f;
        assertEquals(gas,RM11ControllerAxisOrderV49058.first(true,brake,gas),0f);
        assertEquals(brake,RM11ControllerAxisOrderV49058.second(true,brake,gas),0f);
        assertEquals(brake,RM11ControllerAxisOrderV49058.first(false,brake,gas),0f);
        assertEquals(gas,RM11ControllerAxisOrderV49058.second(false,brake,gas),0f);
    }
    @Test public void nullAndFullPressureAndNeutralPassThrough() {
        for(boolean swap:new boolean[]{true,false}) {
            assertEquals(0f,RM11ControllerAxisOrderV49058.first(swap,0f,0f),0f);
            assertEquals(0f,RM11ControllerAxisOrderV49058.second(swap,0f,0f),0f);
            assertEquals(1f,RM11ControllerAxisOrderV49058.first(swap,1f,1f),0f);
            assertEquals(1f,RM11ControllerAxisOrderV49058.second(swap,1f,1f),0f);
        }
    }
}
