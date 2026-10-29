package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

/** XInput 1.4 touch gamepad: analog steering + independent analog pedals. */
public final class RM11VirtualGamepadOverlayV49037 extends FrameLayout {
    private final Activity activity;
    private final RM11VirtualXInputV49037 controller;
    private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
    private final java.util.ArrayList<View> buttons=new java.util.ArrayList<>();
    private boolean shown=true;
    private TextView toggle,graphicsMode;
    private int dp(float d){return (int)(d*getResources().getDisplayMetrics().density+0.5f);}
    private void color(Canvas c,int argb){paint.setColor(argb);paint.setStyle(Paint.Style.FILL);}
    private void circle(Canvas c,float x,float y,float r,int shade) {
        color(c,shade);c.drawCircle(x,y,r,paint);
    }
    private void rect(Canvas c,float l,float t,float r,float b,float radius,int shade) {
        color(c,shade);c.drawRoundRect(l,t,r,b,radius,radius,paint);
    }
    private void text(Canvas c,String label,float x,float y,int size) {
        color(c,0xffffffff);paint.setTextSize(dp(size));paint.setTextAlign(Paint.Align.CENTER);
        paint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        c.drawText(label,x,y,paint);
    }
    private void at(View v,int w,int h,int gravity,int l,int t,int r,int b){
        FrameLayout.LayoutParams lp=new FrameLayout.LayoutParams(dp(w),dp(h),gravity);
        lp.setMargins(dp(l),dp(t),dp(r),dp(b));
        addView(v,lp);
        buttons.add(v);
    }
    private abstract class Control extends View{
        int activePointer=-1;
        Control(){super(activity);setClickable(true);setFocusable(false);}
        abstract void change(float x,float y,boolean pressed);
        @Override public boolean onTouchEvent(MotionEvent e) {
            int action=e.getActionMasked(),actionIndex=e.getActionIndex();
            switch(action) {
                case MotionEvent.ACTION_DOWN:
                case MotionEvent.ACTION_POINTER_DOWN:
                    if(activePointer!=-1)return true;
                    activePointer=e.getPointerId(actionIndex);
                    change(e.getX(actionIndex),e.getY(actionIndex),true);invalidate();return true;
                case MotionEvent.ACTION_MOVE:
                    if(activePointer<0)return true;
                    int idx=e.findPointerIndex(activePointer);
                    if(idx>=0)change(e.getX(idx),e.getY(idx),true);
                    invalidate();return true;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_POINTER_UP:
                    if(e.getPointerId(actionIndex)==activePointer){
                        activePointer=-1;change(0,0,false);invalidate();
                    }return true;
                case MotionEvent.ACTION_CANCEL:
                    activePointer=-1;change(0,0,false);invalidate();return true;
                default:return true;
            }
        }
        void cancel(){activePointer=-1;change(0,0,false);invalidate();}
    }
    private final class Stick extends Control {
        float x,y;
        @Override void change(float px,float py,boolean pressed){
            if(!pressed){x=y=0;}
            else{
                float cx=getWidth()/2f,cy=getHeight()/2f;
                float rad=Math.min(getWidth(),getHeight())*.44f;
                x=Math.max(-1,Math.min(1,(px-cx)/rad));
                y=Math.max(-1,Math.min(1,(py-cy)/rad));
                float length=(float)Math.hypot(x,y);
                if(length>1){x/=length;y/=length;}
            }
            controller.steer(x,y);
        }
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);
            float cx=getWidth()/2f,cy=getHeight()/2f,r=Math.min(cx,cy)*.91f;
            circle(c,cx,cy,r,0x55081323);
            circle(c,cx,cy,r*.75f,0x553a5975);
            circle(c,cx+x*r*.65f,cy+y*r*.65f,r*.42f,0xb9d5eaff);
            text(c,"L",cx,cy+r*.12f,15);
        }
    }
    private final class Pedal extends Control{
        private final boolean throttle;
        private float pressure;
        Pedal(boolean gas){throttle=gas;}
        @Override void change(float x,float y,boolean pressed){
            pressure=pressed?Math.max(.28f,Math.min(1f,1.0f-y/Math.max(1f,getHeight()))):0f;
            if(throttle)controller.pedals(brakeValue,pressure);
            else controller.pedals(pressure,gasValue);
            if(throttle)gasValue=pressure;else brakeValue=pressure;
        }
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);
            rect(c,dp(3),dp(3),getWidth()-dp(3),getHeight()-dp(3),dp(20),0x990b1425);
            float h=getHeight()*.76f;
            rect(c,dp(12),getHeight()-dp(12)-h*pressure,
                getWidth()-dp(12),getHeight()-dp(12),dp(13),
                throttle?0xcc17b886:0xccf07848);
            text(c,throttle?"RT":"LT",getWidth()/2f,dp(35),16);
            text(c,throttle?"بنزين":"فرامل",getWidth()/2f,getHeight()-dp(17),12);
        }
    }
    private float gasValue,brakeValue;
    private final class Face extends Control {
        private final String label;
        private final int code;
        private boolean pressed;
        Face(String label,int bit){this.label=label;code=bit;}
        @Override void change(float x,float y,boolean pressed){
            this.pressed=pressed;
            controller.touchButton(code,pressed);
        }
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);
            circle(c,getWidth()/2f,getHeight()/2f,
                Math.min(getWidth(),getHeight())*.46f,
                pressed?0xe666aaef:0x990f2946);
            text(c,label,getWidth()/2f,getHeight()/2f+dp(7),17);
        }
    }
    private TextView top(String caption){
        TextView v=new TextView(activity);
        v.setText(caption);v.setTextColor(0xfff5faff);v.setTextSize(11);
        v.setGravity(Gravity.CENTER);v.setBackgroundColor(0xa8081b31);
        v.setFocusable(false);v.setClickable(true);return v;
    }
    public RM11VirtualGamepadOverlayV49037(Activity activity,
                                            RM11VirtualXInputV49037 controller){
        super(activity);
        this.activity=activity;this.controller=controller;
        setClickable(false);setFocusable(false);setFocusableInTouchMode(false);
        setMotionEventSplittingEnabled(true);setClipChildren(false);
        setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        at(new Stick(),142,142,Gravity.LEFT|Gravity.BOTTOM,16,0,0,14);
        at(new Pedal(false),80,111,Gravity.RIGHT|Gravity.BOTTOM,0,0,190,17);
        at(new Pedal(true),80,111,Gravity.RIGHT|Gravity.BOTTOM,0,0,14,17);
        at(new Face("X",RM11VirtualXInputV49037.X),53,53,
            Gravity.RIGHT|Gravity.BOTTOM,0,0,117,145);
        at(new Face("Y",RM11VirtualXInputV49037.Y),53,53,
            Gravity.RIGHT|Gravity.BOTTOM,0,0,62,198);
        at(new Face("B",RM11VirtualXInputV49037.B),53,53,
            Gravity.RIGHT|Gravity.BOTTOM,0,0,6,145);
        at(new Face("A",RM11VirtualXInputV49037.A),53,53,
            Gravity.RIGHT|Gravity.BOTTOM,0,0,62,91);
        at(new Face("LB",RM11VirtualXInputV49037.LEFT_SHOULDER),58,40,
            Gravity.LEFT|Gravity.TOP,15,15,0,0);
        at(new Face("RB",RM11VirtualXInputV49037.RIGHT_SHOULDER),58,40,
            Gravity.RIGHT|Gravity.TOP,0,15,145,0);
        at(new Face("START",RM11VirtualXInputV49037.START),65,37,
            Gravity.TOP|Gravity.CENTER_HORIZONTAL,75,13,0,0);
        at(new Face("BACK",RM11VirtualXInputV49037.BACK),65,37,
            Gravity.TOP|Gravity.CENTER_HORIZONTAL,0,13,75,0);
        toggle=top("🎮 إخفاء");
        toggle.setOnClickListener(v->{
            shown=!shown;
            for(View b:buttons)if(b!=toggle&&b!=graphicsMode){
                if(!shown && b instanceof Control)((Control)b).cancel();
                b.setVisibility(shown?VISIBLE:GONE);
            }
            toggle.setText(shown?"🎮 إخفاء":"🎮 إظهار");
        });
        at(toggle,85,38,Gravity.TOP|Gravity.RIGHT,0,9,11,0);
        graphicsMode=top("تقليل الوميض: OFF");
        boolean mode=activity.getSharedPreferences("rm11_carx_graphics",0)
                .getBoolean("tearfree",false);
        graphicsMode.setText(mode?"تقليل الوميض: ON":"تقليل الوميض: OFF");
        graphicsMode.setOnClickListener(v->{
            boolean next=!activity.getSharedPreferences("rm11_carx_graphics",0)
                    .getBoolean("tearfree",false);
            activity.getSharedPreferences("rm11_carx_graphics",0)
                    .edit().putBoolean("tearfree",next).apply();
            graphicsMode.setText(next?"تقليل الوميض: ON":"تقليل الوميض: OFF");
            Toast.makeText(activity,"أعد تشغيل اللعبة لتطبيق وضع الرسوميات",Toast.LENGTH_LONG).show();
        });
        at(graphicsMode,137,36,Gravity.TOP|Gravity.LEFT,14,64,0,0);
    }
    public void releaseAll(){
        for(View v:buttons)if(v instanceof Control)((Control)v).cancel();
        gasValue=brakeValue=0;
    }
}
