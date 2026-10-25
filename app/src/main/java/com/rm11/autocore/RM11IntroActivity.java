package com.rm11.autocore;

import android.app.Activity;
import android.animation.ValueAnimator;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Shader;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;

/**
 * Nonblocking welcome transition. This is a presentation animation only:
 * actual Wine readiness still belongs to RM11NativeWineActivity.
 */
public final class RM11IntroActivity extends Activity {
    private final Handler handler=new Handler(Looper.getMainLooper());
    private boolean launched;
    private IntroScene scene;
    private final Runnable launch=()->openDesktop();
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION|
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE|
                View.SYSTEM_UI_FLAG_HIDE_NAVIGATION|
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
        FrameLayout root=new FrameLayout(this);
        root.setBackgroundColor(0xff07101e);
        scene=new IntroScene();
        root.addView(scene,new FrameLayout.LayoutParams(-1,-1));
        TextView skip=new TextView(this);
        skip.setText("تخطي  ›");
        skip.setTextColor(Color.WHITE);
        skip.setTextSize(15);
        skip.setGravity(Gravity.CENTER);
        skip.setBackgroundColor(0x66305477);
        int dp=Math.round(getResources().getDisplayMetrics().density);
        FrameLayout.LayoutParams p=new FrameLayout.LayoutParams(90*dp,48*dp,Gravity.TOP|Gravity.RIGHT);
        p.setMargins(0,12*dp,16*dp,0);
        root.addView(skip,p);
        skip.setOnClickListener(v->openDesktop());
        setContentView(root);
        handler.postDelayed(launch,1550);
    }
    private void openDesktop() {
        if(launched||isFinishing())return;
        launched=true;
        handler.removeCallbacks(launch);
        startActivity(new Intent(this,RM11NativeWineActivity.class));
        finish();
        overridePendingTransition(android.R.anim.fade_in,android.R.anim.fade_out);
    }
    @Override public void onBackPressed() { openDesktop(); }
    @Override protected void onDestroy() {
        handler.removeCallbacks(launch);
        if(scene!=null)scene.stop();
        super.onDestroy();
    }
    private final class IntroScene extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        private final ValueAnimator timer=ValueAnimator.ofFloat(0f,1f);
        private float progress;
        IntroScene() {
            super(RM11IntroActivity.this);
            timer.setDuration(1500);
            timer.addUpdateListener(a->{
                progress=(float)a.getAnimatedValue();
                invalidate();
            });
            timer.start();
        }
        void stop() {timer.cancel();}
        @Override protected void onDraw(Canvas c) {
            super.onDraw(c);
            float w=getWidth(),h=getHeight();
            float u=Math.min(w,h);
            c.drawColor(0xff061120);
            paint.setShader(new LinearGradient(0,0,w,h,
                    new int[]{0xff081426,0xff112f50,0xff061320},null,Shader.TileMode.CLAMP));
            c.drawRect(0,0,w,h,paint);
            paint.setShader(null);
            // Animated perspective grid, intentionally no image/network asset.
            for(int i=0;i<25;i++) {
                float x=w*i/24f;
                paint.setColor(0x2733baff);
                paint.setStrokeWidth(1f);
                c.drawLine(x,0,x,h,paint);
            }
            for(int i=0;i<12;i++) {
                float y=h*i/11f;
                paint.setColor(0x1733baff);
                paint.setStrokeWidth(1f);
                c.drawLine(0,y,w,y,paint);
            }
            float glow=(float)Math.sin(progress*Math.PI);
            paint.setColor(Color.argb((int)(20+45*glow),40,185,255));
            c.drawCircle(w*.5f,h*.47f,u*(.27f+.04f*progress),paint);
            paint.setColor(0xfff4f9ff);
            paint.setTypeface(android.graphics.Typeface.create("sans-serif-black",1));
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTextSize(u*.14f);
            c.drawText("RM11",w*.5f,h*.43f,paint);
            paint.setColor(0xff70d8ff);
            paint.setTextSize(u*.043f);
            paint.setLetterSpacing(0);
            c.drawText("WINCORE  •  NATIVE DESKTOP",w*.5f,h*.54f,paint);
            paint.setColor(0xffc5d6e9);
            paint.setTextSize(u*.027f);
            c.drawText("INITIALIZING WINDOWS DISPLAY",w*.5f,h*.64f,paint);
            float bx=w*.33f,by=h*.7f,bw=w*.34f,bh=Math.max(4f,u*.009f);
            paint.setColor(0x553b7193);
            c.drawRoundRect(bx,by,bx+bw,by+bh,bh,bh,paint);
            paint.setColor(0xff62cfff);
            c.drawRoundRect(bx,by,bx+bw*progress,by+bh,bh,bh,paint);
        }
    }
}
