package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * RM11 v4.90.35: genuine hold-to-key Android touch driving controls.
 *
 * This is an unfocusable overlay on the existing live Termux Lorie/X11 view:
 * buttons transmit key DOWN on touch and key UP on release, not Android
 * accessibility events, synthetic mouse clicks, or repeated single key taps.
 * Different child buttons permit simultaneous W+A/W+D using Android's
 * split MotionEvents. Everything outside the small controls remains touch-
 * transparent to the underlying mouse/game surface.
 */
public final class RM11CarXTouchControls extends FrameLayout {
    public interface KeySink {
        void key(int androidKeyCode,boolean down);
    }
    public interface VisibilityListener {
        void changed(boolean visible);
    }

    private final KeySink sink;
    private final VisibilityListener visibilityListener;
    private final List<HoldKey> controls=new ArrayList<>();
    private final TextView toggle;
    private boolean controlsVisible=true;

    private int dp(float amount) {
        return Math.round(getResources().getDisplayMetrics().density*amount);
    }
    private static GradientDrawable background(int color,int radiusPx,int strokeColor,int strokePx) {
        GradientDrawable result=new GradientDrawable();
        result.setColor(color);
        result.setCornerRadius(radiusPx);
        result.setStroke(strokePx,strokeColor);
        return result;
    }
    private TextView label(String text,int sp) {
        TextView v=new TextView(getContext());
        v.setText(text);
        v.setTextSize(sp);
        v.setTextColor(0xfff8fbff);
        v.setGravity(Gravity.CENTER);
        v.setTypeface(Typeface.create("sans-serif",Typeface.BOLD));
        v.setFocusable(false);
        v.setFocusableInTouchMode(false);
        v.setIncludeFontPadding(false);
        v.setPadding(dp(5),dp(3),dp(5),dp(3));
        return v;
    }
    private void at(View control,int width,int height,int gravity,int left,int top,int right,int bottom) {
        FrameLayout.LayoutParams params=new FrameLayout.LayoutParams(
                dp(width),dp(height),gravity);
        params.setMargins(dp(left),dp(top),dp(right),dp(bottom));
        addView(control,params);
    }

    private final class HoldKey {
        final int key;
        final TextView surface;
        final Set<Integer> pointers=new HashSet<>();
        boolean down;

        HoldKey(String text,int keyCode,int fontSize) {
            key=keyCode;
            surface=label(text,fontSize);
            surface.setBackground(background(0xb80a1c31,dp(17),0xc5ffffff,dp(1.5f)));
            surface.setClickable(true);
            // Child does not steal focus from the real Lorie keyboard target.
            surface.setFocusable(false);
            surface.setOnTouchListener((view,event)->{
                int action=event.getActionMasked();
                int index=event.getActionIndex();
                switch(action){
                    case MotionEvent.ACTION_DOWN:
                    case MotionEvent.ACTION_POINTER_DOWN:
                        pointers.add(event.getPointerId(index));
                        pressed(true);
                        return true;
                    case MotionEvent.ACTION_POINTER_UP:
                    case MotionEvent.ACTION_UP:
                        pointers.remove(event.getPointerId(index));
                        if(action==MotionEvent.ACTION_UP)pointers.clear();
                        pressed(!pointers.isEmpty());
                        return true;
                    case MotionEvent.ACTION_CANCEL:
                        pointers.clear();
                        pressed(false);
                        return true;
                    default:
                        return true;
                }
            });
            controls.add(this);
        }

        private void pressed(boolean shouldDown){
            if(down==shouldDown)return;
            down=shouldDown;
            surface.setBackground(shouldDown
                    ?background(0xe93a6383,dp(17),0xffe1f9ff,dp(2))
                    :background(0xb80a1c31,dp(17),0xc5ffffff,dp(1.5f)));
            sink.key(key,shouldDown);
        }
        void release(){pointers.clear();pressed(false);}
    }

    private void hold(String title,int code,int fontSize,int w,int h,int gravity,
                      int l,int t,int r,int b) {
        HoldKey button=new HoldKey(title,code,fontSize);
        at(button.surface,w,h,gravity,l,t,r,b);
    }

    public RM11CarXTouchControls(Activity activity,KeySink keySink,
                                 VisibilityListener onVisibility) {
        super(activity);
        if(keySink==null)throw new IllegalArgumentException("KeySink required");
        sink=keySink;
        visibilityListener=onVisibility;
        setClipChildren(false);
        setClipToPadding(false);
        setMotionEventSplittingEnabled(true);
        setClickable(false);
        setFocusable(false);
        setFocusableInTouchMode(false);
        setLayoutDirection(View.LAYOUT_DIRECTION_LTR);

        // Standard CarX Street PC keyboard input: W/S acceleration and brake,
        // A/D steering, Space handbrake; escape opens the in-game menu.
        hold("◀\nيسار",KeyEvent.KEYCODE_A,14,
                78,78,Gravity.LEFT|Gravity.BOTTOM,18,0,0,22);
        hold("يمين\n▶",KeyEvent.KEYCODE_D,14,
                78,78,Gravity.LEFT|Gravity.BOTTOM,109,0,0,22);
        hold("هاند بريك\nSPACE",KeyEvent.KEYCODE_SPACE,11,
                99,68,Gravity.RIGHT|Gravity.BOTTOM,0,0,237,25);
        hold("فرامل\nS",KeyEvent.KEYCODE_S,14,
                92,84,Gravity.RIGHT|Gravity.BOTTOM,0,0,127,20);
        hold("بنزين\nW",KeyEvent.KEYCODE_W,14,
                92,84,Gravity.RIGHT|Gravity.BOTTOM,0,0,19,20);
        hold("ESC",KeyEvent.KEYCODE_ESCAPE,13,
                65,42,Gravity.TOP|Gravity.LEFT,16,13,0,0);

        toggle=label("إخفاء التحكم",12);
        toggle.setBackground(background(0xb80a1c31,dp(13),0xaaffffff,dp(1)));
        toggle.setClickable(true);
        toggle.setOnClickListener(v->setControlsVisible(!controlsVisible));
        at(toggle,112,40,Gravity.RIGHT|Gravity.TOP,0,12,15,0);
        // Leave center free for driving and Lorie full-screen mouse gestures.
    }

    public void setControlsVisible(boolean visible) {
        if(controlsVisible==visible)return;
        if(!visible)releaseAll();
        controlsVisible=visible;
        for(HoldKey control:controls)
            control.surface.setVisibility(visible?View.VISIBLE:View.GONE);
        toggle.setText(visible?"إخفاء التحكم":"🎮 إظهار التحكم");
        if(visibilityListener!=null)visibilityListener.changed(visible);
    }
    public boolean controlsVisible(){return controlsVisible;}
    /** Critical on pause, app exit, Android cancel and when hiding controls. */
    public void releaseAll() {
        for(HoldKey control:controls)control.release();
    }
}
