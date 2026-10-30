package com.rm11.autocore;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.drawable.GradientDrawable;
import android.os.SystemClock;
import android.view.View;

/**
 * Six persistent, selectable visual profiles for the Android HOME UI only.
 * No Wine/XInput/graphics-driver state and no game EXE or prefix changes.
 */
public final class RM11UiThemesV49059 {
    private RM11UiThemesV49059() {}
    private static final String PREFS="rm11_ui_appearance_v49059";
    public static final int COUNT=6;
    public static final String[] NAMES={
        "السينمائي المتحرك","القتالي الاحترافي","الرواق ثلاثي الأبعاد",
        "النظيف المتحرك","الزجاجي المستقبلي","المكتبي الغامر"
    };
    public static final String[] DESCRIPTIONS={
        "واجهة سينمائية وبطاقات كبيرة ولمعان أزرق",
        "طابع ألعاب قوي، تفاصيل حمراء وواجهة مركزة",
        "بطاقات أغلفة عائمة وطبقات بعمق بصري",
        "تصميم مريح وخفيف بقوائم واضحة",
        "زجاج مضيء وتوهج هولوغرافي متدرج",
        "مظهر سطح مكتب احترافي ومكتبة متعددة الأقسام"
    };
    private static final int[] ACCENTS={
        0xff36a8ff,0xffff525f,0xffffbd69,0xff3cdda8,0xff9a74ff,0xff69baff
    };
    private static final int[] TOP={
        0xff07172a,0xff240a18,0xff261b2b,0xff0a181c,0xff14122e,0xff0b2030
    };
    private static final int[] BOTTOM={
        0xff080c15,0xff100b16,0xff101017,0xff0b1315,0xff080f22,0xff101b2b
    };
    public static final int AUTO=0,PORTRAIT=1,LANDSCAPE=2;
    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS,Context.MODE_PRIVATE);
    }
    public static int selected(Context c) {
        return clamp(prefs(c).getInt("theme",0));
    }
    public static void select(Context c,int index) {
        prefs(c).edit().putInt("theme",clamp(index)).apply();
    }
    public static int orientation(Context c) {
        int v=prefs(c).getInt("orientation",AUTO);
        return v>=AUTO&&v<=LANDSCAPE?v:AUTO;
    }
    public static void setOrientation(Context c,int v) {
        prefs(c).edit().putInt("orientation",v>=AUTO&&v<=LANDSCAPE?v:AUTO).apply();
    }
    public static boolean motion(Context c) {
        return prefs(c).getBoolean("motion",true);
    }
    public static void setMotion(Context c,boolean enabled) {
        prefs(c).edit().putBoolean("motion",enabled).apply();
    }
    public static int clamp(int i) {return Math.max(0,Math.min(COUNT-1,i));}
    public static int accent(int i) {return ACCENTS[clamp(i)];}
    public static int background(int i) {return BOTTOM[clamp(i)];}
    public static int top(int i) {return TOP[clamp(i)];}
    public static int cardColor(int i) {
        switch(clamp(i)) {
            case 1:return 0xee231722;
            case 2:return 0xee322734;
            case 3:return 0xf0182528;
            case 4:return 0xb7212040;
            case 5:return 0xe9193040;
            default:return 0xd416253a;
        }
    }
    public static GradientDrawable panel(int i,int radiusDp,float density) {
        int profile=clamp(i);
        GradientDrawable d=new GradientDrawable(GradientDrawable.Orientation.TL_BR,
            new int[]{cardColor(profile),BOTTOM[profile]});
        d.setCornerRadius(radiusDp*density);
        d.setStroke(Math.max(1,(int)density),
            (accent(profile)&0x00ffffff)|0x66000000);
        return d;
    }
    public static GradientDrawable button(int i,int radiusDp,float density) {
        int color=accent(i);
        GradientDrawable d=new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{color,blend(color,0xff0c1526,.45f)});
        d.setCornerRadius(radiusDp*density);
        return d;
    }
    private static int blend(int a,int b,float amount){
        return Color.rgb(
            Math.round(Color.red(a)*(1-amount)+Color.red(b)*amount),
            Math.round(Color.green(a)*(1-amount)+Color.green(b)*amount),
            Math.round(Color.blue(a)*(1-amount)+Color.blue(b)*amount));
    }
    public static void applyOrientation(Activity activity) {
        int mode=orientation(activity);
        activity.setRequestedOrientation(
            mode==PORTRAIT?ActivityInfo.SCREEN_ORIENTATION_PORTRAIT:
            mode==LANDSCAPE?ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE:
                ActivityInfo.SCREEN_ORIENTATION_FULL_SENSOR);
    }
    /** Only HOME and FILES adopt the user rotation preference; games stay landscape. */
    public static int libraryColumns(int profile,boolean portrait) {
        if(profile==3||profile==5)return 1;
        if(profile==2||profile==4)return portrait?2:4;
        return portrait?2:3;
    }
    /** Lightweight procedural depth effect; no GPU context or wallpaper assets. */
    public static final class AnimatedScene extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        private final int profile;
        private boolean enabled;
        private boolean running;
        public AnimatedScene(Context context,int profile) {
            super(context);
            this.profile=clamp(profile);
            enabled=motion(context);
            setLayerType(View.LAYER_TYPE_NONE,null);
        }
        @Override protected void onAttachedToWindow() {
            super.onAttachedToWindow();running=true;
            if(enabled)postInvalidateDelayed(42);
        }
        @Override protected void onDetachedFromWindow() {
            running=false;super.onDetachedFromWindow();
        }
        @Override protected void onDraw(Canvas c) {
            super.onDraw(c);
            float w=getWidth(),h=getHeight();
            if(w<=0||h<=0)return;
            paint.setShader(new LinearGradient(0,0,w,h,TOP[profile],BOTTOM[profile],
                Shader.TileMode.CLAMP));
            c.drawRect(0,0,w,h,paint);paint.setShader(null);
            float t=enabled?(SystemClock.uptimeMillis()%16000L)/16000f:0.22f;
            float distance=Math.min(w,h);
            for(int i=0;i<4;i++){
                float x=w*(.15f+.24f*i)+distance*.10f*(float)Math.sin(t*6.28318+i);
                float y=h*(.23f+.17f*(i%3))+distance*.09f*(float)Math.cos(t*6.28318+i);
                int a=(18+i*4)<<24|(accent(profile)&0xffffff);
                paint.setShader(new RadialGradient(x,y,distance*.60f,
                    new int[]{a,a&0x00ffffff},null,Shader.TileMode.CLAMP));
                c.drawCircle(x,y,distance*.60f,paint);
                paint.setShader(null);
            }
            paint.setStrokeWidth(Math.max(1,w/850f));
            paint.setColor((accent(profile)&0xffffff)|0x1c000000);
            for(int i=0;i<9;i++){
                float y=h*(i+1)/10f;
                if(profile==3){c.drawLine(0,y,w,y,paint);continue;}
                float sway=enabled?12f*(float)Math.sin(t*6.28318+i*.7):0;
                c.drawLine(0,y+sway,w,y+sway,paint);
            }
            if(enabled&&running)postInvalidateDelayed(42);
        }
    }
}
