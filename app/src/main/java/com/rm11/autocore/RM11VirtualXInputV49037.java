package com.rm11.autocore;

import android.content.Context;
import android.view.KeyEvent;
import android.view.MotionEvent;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Single virtual Xbox controller on a shared 64-byte mmap across Android
 * and the app-local Win64 XInput DLL. No root, uinput, Android key injection,
 * or external VirtualPad APK necessary. All changes are confined to CarX.
 */
public final class RM11VirtualXInputV49037 {
    private static final int SIZE=64,MAGIC=0x524d3131,VERSION=1;
    private final RandomAccessFile file;
    private final FileChannel channel;
    private final MappedByteBuffer memory;
    private int sequence=0;
    private boolean connected=true;
    // Source-independent inputs, preserving true analog trigger pressure.
    private float touchLX,touchLY,touchRX,touchRY,touchLT,touchRT;
    private float physicalLX,physicalLY,physicalRX,physicalRY,physicalLT,physicalRT;
    private int touchButtons,physicalButtons,physicalHatButtons;
    private boolean digitalPhysicalLT,digitalPhysicalRT;
    public static final int DPAD_UP=0x0001,DPAD_DOWN=0x0002,DPAD_LEFT=0x0004,
            DPAD_RIGHT=0x0008,START=0x0010,BACK=0x0020,
            LEFT_THUMB=0x0040,RIGHT_THUMB=0x0080,
            LEFT_SHOULDER=0x0100,RIGHT_SHOULDER=0x0200,
            A=0x1000,B=0x2000,X=0x4000,Y=0x8000;

    public static Path statePath(Context context) {
        return new File(context.getFilesDir(),"rm11-v49037-xinput-state.bin").toPath();
    }
    public RM11VirtualXInputV49037(Context ctx) throws Exception {
        File target=statePath(ctx).toFile();
        if(target.isDirectory()||java.nio.file.Files.isSymbolicLink(target.toPath()))
            throw new java.io.IOException("VIRTUAL_PAD_STATE_UNSAFE");
        file=new RandomAccessFile(target,"rw");
        file.setLength(SIZE);
        channel=file.getChannel();
        memory=channel.map(FileChannel.MapMode.READ_WRITE,0,SIZE);
        memory.order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<SIZE;i++)memory.put(i,(byte)0);
        memory.putInt(0,MAGIC);
        memory.putInt(4,VERSION);
        commit();
    }
    private static float bound(float v) {
        return Float.isFinite(v)?Math.max(-1,Math.min(1,v)):0;
    }
    private static float pressure(float v) {
        return Math.max(0,bound(v));
    }
    private static float choose(float touch,float physical) {
        return Math.abs(touch)>0.025f?touch:physical;
    }
    private static short stick(float value) {
        float v=bound(value);
        return (short)(v>=0?Math.round(v*32767):Math.round(v*32768));
    }
    private static byte trigger(float value) {
        return (byte)Math.round(pressure(value)*255);
    }
    private synchronized void commit(){
        // seq writer contract: odd indicates writing, even indicates stable.
        // Android/Win32 both little-endian, the DLL retries if seq changes.
        sequence+=2;
        memory.putInt(8,sequence-1);
        memory.putInt(12,connected?1:0);
        memory.putShort(16,(short)(touchButtons|physicalButtons|physicalHatButtons));
        memory.put(18,trigger(Math.max(touchLT,
            Math.max(physicalLT,digitalPhysicalLT?1f:0f))));
        memory.put(19,trigger(Math.max(touchRT,
            Math.max(physicalRT,digitalPhysicalRT?1f:0f))));
        memory.putShort(20,stick(choose(touchLX,physicalLX)));
        memory.putShort(22,stick(choose(touchLY,physicalLY)));
        memory.putShort(24,stick(choose(touchRX,physicalRX)));
        memory.putShort(26,stick(choose(touchRY,physicalRY)));
        memory.putInt(8,sequence);
        // memory.force only on initialization; shared mmap is coherent, no
        // disk sync on every joystick motion. Avoid per-frame I/O.
    }
    public synchronized void steer(float x,float y) {
        touchLX=bound(x);
        touchLY=bound(-y); // Android downward-positive -> XInput upward-positive
        commit();
    }
    public synchronized void rightStick(float x,float y) {
        touchRX=bound(x);
        touchRY=bound(-y);
        commit();
    }
    public synchronized void pedals(float brake,float gas) {
        touchLT=pressure(brake);
        touchRT=pressure(gas);
        commit();
    }
    public synchronized void touchButton(int xinputBit,boolean pressed) {
        if(pressed)touchButtons|=xinputBit;else touchButtons&=~xinputBit;
        commit();
    }
    public synchronized void physicalAxes(float x,float y,float rx,float ry,
                                           float lt,float rt,float hatX,float hatY) {
        physicalLX=bound(x);
        physicalLY=bound(-y);
        physicalRX=bound(rx);
        physicalRY=bound(-ry);
        physicalLT=pressure(lt);
        physicalRT=pressure(rt);
        physicalHatButtons=0;
        if(hatX<-.5f)physicalHatButtons|=DPAD_LEFT;
        if(hatX>.5f)physicalHatButtons|=DPAD_RIGHT;
        if(hatY<-.5f)physicalHatButtons|=DPAD_UP;
        if(hatY>.5f)physicalHatButtons|=DPAD_DOWN;
        commit();
    }
    private static int physicalMapping(int keycode) {
        switch(keycode){
            case KeyEvent.KEYCODE_BUTTON_A:return A;
            case KeyEvent.KEYCODE_BUTTON_B:return B;
            case KeyEvent.KEYCODE_BUTTON_X:return X;
            case KeyEvent.KEYCODE_BUTTON_Y:return Y;
            case KeyEvent.KEYCODE_BUTTON_L1:return LEFT_SHOULDER;
            case KeyEvent.KEYCODE_BUTTON_R1:return RIGHT_SHOULDER;
            case KeyEvent.KEYCODE_BUTTON_THUMBL:return LEFT_THUMB;
            case KeyEvent.KEYCODE_BUTTON_THUMBR:return RIGHT_THUMB;
            case KeyEvent.KEYCODE_BUTTON_START:return START;
            case KeyEvent.KEYCODE_BUTTON_SELECT:return BACK;
            case KeyEvent.KEYCODE_DPAD_UP:return DPAD_UP;
            case KeyEvent.KEYCODE_DPAD_DOWN:return DPAD_DOWN;
            case KeyEvent.KEYCODE_DPAD_LEFT:return DPAD_LEFT;
            case KeyEvent.KEYCODE_DPAD_RIGHT:return DPAD_RIGHT;
            default:return 0;
        }
    }
    public static boolean handlesPhysicalButton(int keycode) {
        return physicalMapping(keycode)!=0
            ||keycode==KeyEvent.KEYCODE_BUTTON_L2
            ||keycode==KeyEvent.KEYCODE_BUTTON_R2;
    }
    public synchronized boolean physicalKey(int keycode,boolean pressed) {
        if(keycode==KeyEvent.KEYCODE_BUTTON_L2){
            digitalPhysicalLT=pressed;commit();return true;
        }
        if(keycode==KeyEvent.KEYCODE_BUTTON_R2){
            digitalPhysicalRT=pressed;commit();return true;
        }
        int bit=physicalMapping(keycode);
        if(bit==0)return false;
        if(pressed)physicalButtons|=bit;else physicalButtons&=~bit;
        commit();
        return true;
    }
    public synchronized void physicalDisconnect(){
        physicalLX=physicalLY=physicalRX=physicalRY=physicalLT=physicalRT=0;
        physicalButtons=0;
        physicalHatButtons=0;
        digitalPhysicalLT=digitalPhysicalRT=false;
        commit();
    }
    /** Hide touchscreen without resetting a still-connected physical controller. */
    public synchronized void releaseTouchOnly(){
        touchLX=touchLY=touchRX=touchRY=touchLT=touchRT=0;
        touchButtons=0;
        commit();
    }
    public synchronized void releaseAll(){
        physicalDisconnect();
        releaseTouchOnly();
    }
    public synchronized int readCount() {return memory.getInt(32);}
    public synchronized int capabilitiesReadCount(){return memory.getInt(36);}
    public synchronized void close()throws Exception {
        releaseAll();
        channel.close();
        file.close();
    }
}
