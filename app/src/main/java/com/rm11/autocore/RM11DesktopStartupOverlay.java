package com.rm11.autocore;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Shader;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.FrameLayout;
import android.widget.TextView;

/**
 * Animated native startup curtain. Stays on TOP of Lorie's Android SurfaceView
 * until Winefile's actual white UI pixels have appeared. This prevents the
 * user seeing the black X.Org boot framebuffer between Intro and Windows.
 *
 * The animation is decorative: it does not indicate a fictitious percentage.
 * The caller, not a fixed timer, decides when genuine pixels are ready.
 */
public final class RM11DesktopStartupOverlay extends FrameLayout {
    private final Scene scene;
    private final TextView status;
    private boolean exiting;
    public RM11DesktopStartupOverlay(Context context) {
        super(context);
        setClickable(true);
        setFocusable(false);
        setBackgroundColor(0xff07101c);
        scene=new Scene(context);
        addView(scene,new LayoutParams(-1,-1));
        status=new TextView(context);
        status.setText("جاري تجهيز واجهة Windows...");
        status.setTextSize(16f);
        status.setTextColor(0xffbad7ee);
        status.setGravity(Gravity.CENTER);
        LayoutParams textLayout=new LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,dp(64),Gravity.BOTTOM|Gravity.CENTER_HORIZONTAL);
        textLayout.setMargins(dp(24),0,dp(24),dp(25));
        addView(status,textLayout);
        setElevation(dp(12));
    }
    private int dp(float v) {
        return (int)(v*getResources().getDisplayMetrics().density+.5f);
    }
    public void updateStatus(String text) {
        if(!exiting && text!=null && text.length()>0)status.setText(text);
    }
    public void revealDesktop(Runnable completion) {
        if(exiting)return;
        exiting=true;
        animate().alpha(0).setDuration(210).withEndAction(()->{
            scene.stop();
            if(getParent() instanceof ViewGroup)
                ((ViewGroup)getParent()).removeView(this);
            if(completion!=null)completion.run();
        }).start();
    }
    public void stop() {
        animate().cancel();
        scene.stop();
    }
    private static final class Scene extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        private final ValueAnimator scan=ValueAnimator.ofFloat(0f,1f);
        private float phase;
        Scene(Context ctx) {
            super(ctx);
            scan.setDuration(2800);
            scan.setInterpolator(new LinearInterpolator());
            scan.setRepeatCount(ValueAnimator.INFINITE);
            scan.addUpdateListener(a->{
                phase=(float)a.getAnimatedValue();
                invalidate();
            });
            scan.start();
        }
        void stop(){scan.cancel();}
        @Override protected void onDraw(Canvas c) {
            super.onDraw(c);
            float w=getWidth(),h=getHeight(),u=Math.min(w,h);
            paint.setShader(new LinearGradient(0,0,w,h,
                    new int[]{0xff06101f,0xff122d4d,0xff07101d},
                    null,Shader.TileMode.CLAMP));
            c.drawRect(0,0,w,h,paint);
            paint.setShader(null);
            paint.setStrokeWidth(Math.max(1f,u*.0013f));
            for(int i=0;i<31;i++) {
                float x=w*i/30f;
                paint.setColor(0x25369bd2);
                c.drawLine(x,0,x,h,paint);
            }
            for(int i=0;i<15;i++) {
                float y=h*i/14f;
                paint.setColor(0x193b90d5);
                c.drawLine(0,y,w,y,paint);
            }
            float x=w*(.16f+.68f*phase);
            paint.setShader(new LinearGradient(x-u*.14f,0,x+u*.14f,0,
                    new int[]{0x0049cfff,0x425ee9ff,0x0049cfff},
                    null,Shader.TileMode.CLAMP));
            c.drawRect(x-u*.14f,0,x+u*.14f,h,paint);
            paint.setShader(null);
            paint.setColor(0x2439c7ff);
            c.drawCircle(w*.5f,h*.43f,u*(.20f+.024f*phase),paint);
            paint.setColor(0xfff3faff);
            paint.setTypeface(android.graphics.Typeface.create(
                    "sans-serif-black",android.graphics.Typeface.BOLD));
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTextSize(u*.137f);
            c.drawText("RM11",w*.5f,h*.435f,paint);
            paint.setTypeface(android.graphics.Typeface.create(
                    "sans-serif-medium",android.graphics.Typeface.NORMAL));
            paint.setTextSize(u*.045f);
            paint.setColor(0xff7cddff);
            c.drawText("WINCORE  •  WINDOWS DESKTOP",w*.5f,h*.535f,paint);
            float progress=(phase*1.8f)%1f;
            float by=h*.635f,bx=w*.35f,bw=w*.3f,bh=Math.max(4f,u*.006f);
            paint.setColor(0x66447ea8);
            c.drawRoundRect(bx,by,bx+bw,by+bh,bh,bh,paint);
            paint.setColor(0xff72dcff);
            float left=bx+bw*Math.max(0,progress-.24f);
            float right=bx+bw*progress;
            c.drawRoundRect(left,by,Math.max(left+1,right),by+bh,bh,bh,paint);
        }
    }
}
