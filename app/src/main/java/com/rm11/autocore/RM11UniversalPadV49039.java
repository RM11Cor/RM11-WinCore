package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.LinearGradient;
import android.graphics.Shader;
import android.graphics.RectF;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.KeyEvent;
import android.widget.FrameLayout;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

/**
 * Universal full Xbox-style virtual pad across explicit user selected EXEs.
 * Rendered over the live Android Lorie surface (no screenshot bitmap). Uses
 * low-latency direct mapped native XInput, plus immediate per-game keyboard
 * fallback when a Windows game does not poll the XInput provider.
 *
 * Screen controls are REAL touch hit regions with split multitouch, adjustable
 * size / opacity, edit-to-drag placement, persistent per-game profiles.
 */
public final class RM11UniversalPadV49039 extends FrameLayout {
    public interface KeySink { void send(int keyCode,boolean down); }
    private static final int AUTO=0,XINPUT=1,KEYBOARD=2;
    private static final int WHITE=0xfff8fcff;
    private final Activity activity;
    private final RM11VirtualXInputV49037 xinput;
    private final KeySink keyboard;
    private final SharedPreferences prefs;
    private final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);
    private final ArrayList<PadKey> padKeys=new ArrayList<>();
    private final java.util.Map<Integer,Set<String>> keyboardOwners=new java.util.HashMap<>();
    private final TextView settings;
    private final TextView readout;
    private int mode,opacity,size;
    private boolean editing,visible=true;
    private final Runnable poll=new Runnable(){
        @Override public void run(){
            if(!isAttachedToWindow())return;
            int hits=xinput.readCount();
            readout.setText(hits>0?"XInput ● "+hits+" polls"
                    :(mode==KEYBOARD?"KEYBOARD MODE":mode==XINPUT
                      ?"XInput • game not reading":"AUTO • keyboard fallback"));
            readout.setTextColor(hits>0?0xff8ef6bb:0xfff5c98e);
            postDelayed(this,1800);
        }
    };

    private int dp(float v){
        return (int)(v*getResources().getDisplayMetrics().density+0.5f);
    }
    private void text(Canvas c,String label,float x,float y,float size,int color){
        p.reset();p.setAntiAlias(true);p.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        p.setColor(color);p.setTextAlign(Paint.Align.CENTER);p.setTextSize(dp(size));
        c.drawText(label,x,y,p);
    }
    private void rounded(Canvas c,float left,float top,float right,float bottom,float r,boolean pushed){
        p.reset();p.setAntiAlias(true);
        p.setShader(new LinearGradient(0,top,0,bottom,
            pushed?new int[]{0xff455669,0xff101621}:
                   new int[]{0xff35383d,0xff111316,0xff050608},
            pushed?null:new float[]{0,.33f,1},Shader.TileMode.CLAMP));
        RectF rect=new RectF(left,top,right,bottom);
        c.drawRoundRect(rect,r,r,p);
        p.setShader(null);p.setStyle(Paint.Style.STROKE);
        p.setColor(pushed?0xffb6dfff:0xff44494f);p.setStrokeWidth(dp(1.2f));
        c.drawRoundRect(rect,r,r,p);p.setStyle(Paint.Style.FILL);
    }
    private void circle(Canvas c,float x,float y,float radius,boolean pushed){
        p.reset();p.setAntiAlias(true);
        p.setShader(new LinearGradient(0,y-radius,0,y+radius,
            pushed?0xff546d86:0xff31363a,0xff050608,Shader.TileMode.CLAMP));
        c.drawCircle(x,y,radius,p);
        p.setShader(null);p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(dp(1.2f));p.setColor(pushed?0xffacd8ff:0xff434a50);
        c.drawCircle(x,y,radius,p);p.setStyle(Paint.Style.FILL);
    }
    /** Multiple controls can own a key. Releasing throttle must never
     *  cancel W while the left stick still holds forward, and vice versa.
     */
    private void key(int key,boolean down,String source){
        if(key==0)return;
        if(down && (mode==XINPUT ||(mode==AUTO && xinput.readCount()>0)))
            return;
        Set<String> owners=keyboardOwners.get(key);
        if(down){
            if(owners==null){
                owners=new HashSet<>();keyboardOwners.put(key,owners);
            }
            if(owners.add(source) && owners.size()==1)keyboard.send(key,true);
        } else if(owners!=null && owners.remove(source) && owners.isEmpty()){
            keyboardOwners.remove(key);keyboard.send(key,false);
        }
    }
    private void releaseKeyboard(){
        for(Integer k:new HashSet<>(keyboardOwners.keySet()))keyboard.send(k,false);
        keyboardOwners.clear();
    }
    private int mapped(String identifier,int defaultKey){
        return prefs.getInt("bind_"+identifier,defaultKey);
    }
    private static boolean isStick(String name){return "L".equals(name)||"R".equals(name);}
    private static boolean isDpad(String name){return name.startsWith("D");}
    private static int bit(String name){
        switch(name){
            case "A":return RM11VirtualXInputV49037.A;
            case "B":return RM11VirtualXInputV49037.B;
            case "X":return RM11VirtualXInputV49037.X;
            case "Y":return RM11VirtualXInputV49037.Y;
            case "LB":return RM11VirtualXInputV49037.LEFT_SHOULDER;
            case "RB":return RM11VirtualXInputV49037.RIGHT_SHOULDER;
            case "L3":return RM11VirtualXInputV49037.LEFT_THUMB;
            case "R3":return RM11VirtualXInputV49037.RIGHT_THUMB;
            case "START":return RM11VirtualXInputV49037.START;
            case "BACK":return RM11VirtualXInputV49037.BACK;
            case "DUP":return RM11VirtualXInputV49037.DPAD_UP;
            case "DDOWN":return RM11VirtualXInputV49037.DPAD_DOWN;
            case "DLEFT":return RM11VirtualXInputV49037.DPAD_LEFT;
            case "DRIGHT":return RM11VirtualXInputV49037.DPAD_RIGHT;
            default:return 0;
        }
    }
    private static int scan(String name){
        switch(name){
            case "A":return KeyEvent.KEYCODE_ENTER;
            case "B":return KeyEvent.KEYCODE_ESCAPE;
            case "X":return KeyEvent.KEYCODE_SPACE;
            case "Y":return KeyEvent.KEYCODE_SHIFT_LEFT;
            case "LB":return KeyEvent.KEYCODE_Q;
            case "RB":return KeyEvent.KEYCODE_E;
            case "L3":return KeyEvent.KEYCODE_CTRL_LEFT;
            case "R3":return KeyEvent.KEYCODE_C;
            case "START":return KeyEvent.KEYCODE_ESCAPE;
            case "BACK":return KeyEvent.KEYCODE_TAB;
            case "DUP":return KeyEvent.KEYCODE_DPAD_UP;
            case "DDOWN":return KeyEvent.KEYCODE_DPAD_DOWN;
            case "DLEFT":return KeyEvent.KEYCODE_DPAD_LEFT;
            case "DRIGHT":return KeyEvent.KEYCODE_DPAD_RIGHT;
            default:return 0;
        }
    }
    private final class PadKey extends View {
        final String name;
        final int w,h;
        final int initialGravity,ml,mt,mr,mb;
        boolean pressed;
        int pointer=-1;
        float stickX,stickY,pressure;
        float lastTouchX,lastTouchY;
        int oldLeft,oldTop;
        PadKey(String n,int width,int height,int gravity,int l,int t,int r,int b){
            super(activity);name=n;w=width;h=height;
            initialGravity=gravity;ml=l;mt=t;mr=r;mb=b;
            setClickable(true);setFocusable(false);
            setAlpha(opacity/100f);
        }
        boolean circleShape(){
            return isStick(name)||isDpad(name)||
                name.equals("A")||name.equals("B")||name.equals("X")||
                name.equals("Y")||name.equals("L3")||name.equals("R3");
        }
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);
            float cx=getWidth()/2f,cy=getHeight()/2f;
            if(isStick(name)){
                float radius=Math.min(cx,cy)*.94f;
                circle(c,cx,cy,radius,false);
                circle(c,cx+stickX*radius*.60f,
                    cy+stickY*radius*.60f,radius*.43f,pressed);
                text(c,name,cx+stickX*radius*.60f,
                    cy+stickY*radius*.60f+dp(7),17,WHITE);
            }else if(circleShape()){
                circle(c,cx,cy,Math.min(cx,cy)*.94f,pressed);
                String label=name;
                if(isDpad(name))label=name.equals("DUP")?"▲":
                     name.equals("DDOWN")?"▼":name.equals("DLEFT")?"◀":"▶";
                text(c,label,cx,cy+dp(7),name.startsWith("D")?19:20,WHITE);
            }else{
                rounded(c,dp(2),dp(2),getWidth()-dp(2),getHeight()-dp(2),
                    dp(13),pressed);
                text(c,name,cx,cy+dp(8),name.length()>4?12:22,WHITE);
            }
            if(editing){
                p.reset();p.setAntiAlias(true);
                p.setColor(0xa0edb260);p.setStyle(Paint.Style.STROKE);
                p.setStrokeWidth(dp(1.3f));
                c.drawRect(0,0,getWidth(),getHeight(),p);p.setStyle(Paint.Style.FILL);
            }
        }
        void update(float touchX,float touchY,boolean down) {
            pressed=down;
            if(isStick(name)){
                if(!down)stickX=stickY=0;
                else {
                    float radius=Math.min(getWidth(),getHeight())*.43f;
                    stickX=Math.max(-1,Math.min(1,(touchX-getWidth()/2f)/radius));
                    stickY=Math.max(-1,Math.min(1,(touchY-getHeight()/2f)/radius));
                    float d=(float)Math.hypot(stickX,stickY);
                    if(d>1){stickX/=d;stickY/=d;}
                }
                if(name.equals("L")){
                    xinput.steer(stickX,stickY);
                    key(mapped("LLEFT",KeyEvent.KEYCODE_A),down&&stickX<-.36f,"LLEFT");
                    key(mapped("LRIGHT",KeyEvent.KEYCODE_D),down&&stickX>.36f,"LRIGHT");
                    key(mapped("LUP",KeyEvent.KEYCODE_W),down&&stickY<-.36f,"LUP");
                    key(mapped("LDOWN",KeyEvent.KEYCODE_S),down&&stickY>.36f,"LDOWN");
                }else{
                    xinput.rightStick(stickX,stickY);
                    key(mapped("RLEFT",KeyEvent.KEYCODE_DPAD_LEFT),down&&stickX<-.36f,"RLEFT");
                    key(mapped("RRIGHT",KeyEvent.KEYCODE_DPAD_RIGHT),down&&stickX>.36f,"RRIGHT");
                    key(mapped("RUP",KeyEvent.KEYCODE_DPAD_UP),down&&stickY<-.36f,"RUP");
                    key(mapped("RDOWN",KeyEvent.KEYCODE_DPAD_DOWN),down&&stickY>.36f,"RDOWN");
                }
            }else if(name.equals("LT")||name.equals("RT")){
                pressure=down?Math.max(.28f,Math.min(1f,
                        1f-touchY/Math.max(1,getHeight()))):0;
                if(name.equals("LT"))brake=pressure;
                else gas=pressure;
                xinput.pedals(brake,gas);
                key(mapped(name,name.equals("LT")?KeyEvent.KEYCODE_S:KeyEvent.KEYCODE_W),
                    down,name);
            }else{
                int code=bit(name);
                if(code!=0)xinput.touchButton(code,down);
                int fallback=scan(name);
                if(fallback!=0)key(mapped(name,fallback),down,name);
            }
            invalidate();
        }
        void cancel(){
            if(pressed||stickX!=0||stickY!=0)update(0,0,false);
            pointer=-1;
        }
        @Override public boolean onTouchEvent(MotionEvent e){
            int action=e.getActionMasked(),index=e.getActionIndex();
            switch(action){
                case MotionEvent.ACTION_DOWN:
                case MotionEvent.ACTION_POINTER_DOWN: {
                    if(pointer!=-1)return true;
                    pointer=e.getPointerId(index);
                    lastTouchX=e.getRawX();lastTouchY=e.getRawY();
                    LayoutParams lp=(LayoutParams)getLayoutParams();
                    oldLeft=lp.leftMargin;oldTop=lp.topMargin;
                    if(!editing)update(e.getX(index),e.getY(index),true);
                    return true;
                }
                case MotionEvent.ACTION_MOVE: {
                    if(pointer==-1)return true;
                    int i=e.findPointerIndex(pointer);
                    if(i<0)return true;
                    if(editing){
                        float dx=e.getRawX()-lastTouchX,dy=e.getRawY()-lastTouchY;
                        LayoutParams lp=(LayoutParams)getLayoutParams();
                        if(lp.gravity!=(Gravity.TOP|Gravity.LEFT)){
                            int[] origin=new int[2],here=new int[2];
                            RM11UniversalPadV49039.this.getLocationOnScreen(origin);
                            getLocationOnScreen(here);
                            lp.gravity=Gravity.TOP|Gravity.LEFT;
                            lp.leftMargin=here[0]-origin[0];
                            lp.topMargin=here[1]-origin[1];
                            lp.rightMargin=lp.bottomMargin=0;
                            oldLeft=lp.leftMargin;oldTop=lp.topMargin;
                            lastTouchX=e.getRawX();lastTouchY=e.getRawY();
                            dx=dy=0;
                        }
                        lp.leftMargin=Math.max(0,Math.min(getWidthSafe()-getWidth(),
                            oldLeft+(int)dx));
                        lp.topMargin=Math.max(0,Math.min(getHeightSafe()-getHeight(),
                            oldTop+(int)dy));
                        setLayoutParams(lp);
                    }else update(e.getX(i),e.getY(i),true);
                    return true;
                }
                case MotionEvent.ACTION_POINTER_UP:
                case MotionEvent.ACTION_UP: {
                    if(e.getPointerId(index)!=pointer)return true;
                    pointer=-1;
                    if(!editing)update(0,0,false);
                    else{
                        LayoutParams lp=(LayoutParams)getLayoutParams();
                        prefs.edit().putFloat("x_"+name,
                             lp.leftMargin/(float)Math.max(1,getWidthSafe()))
                            .putFloat("y_"+name,
                             lp.topMargin/(float)Math.max(1,getHeightSafe())).apply();
                    }
                    return true;
                }
                case MotionEvent.ACTION_CANCEL:
                    cancel();return true;
                default:return true;
            }
        }
    }
    private float gas,brake;
    private int getWidthSafe(){return Math.max(1,getWidth());}
    private int getHeightSafe(){return Math.max(1,getHeight());}
    private void add(String name,int width,int height,int gravity,int l,int t,int r,int b){
        PadKey k=new PadKey(name,width,height,gravity,l,t,r,b);
        padKeys.add(k);
        LayoutParams lp=new LayoutParams(dp(width*size/100f),dp(height*size/100f),gravity);
        lp.setMargins(dp(l),dp(t),dp(r),dp(b));
        addView(k,lp);
        k.post(()->{
            float x=prefs.getFloat("x_"+name,-1);
            float y=prefs.getFloat("y_"+name,-1);
            if(x<0||y<0)return;
            LayoutParams position=(LayoutParams)k.getLayoutParams();
            position.gravity=Gravity.TOP|Gravity.LEFT;
            position.leftMargin=Math.round(x*getWidthSafe());
            position.topMargin=Math.round(y*getHeightSafe());
            position.rightMargin=position.bottomMargin=0;
            k.setLayoutParams(position);
        });
    }
    private TextView top(String label){
        TextView value=new TextView(activity);value.setText(label);
        value.setTextColor(WHITE);value.setTextSize(12);value.setGravity(Gravity.CENTER);
        value.setBackgroundColor(0xcc080c12);value.setFocusable(false);
        value.setClickable(true);return value;
    }
    private void topRight(TextView view,int w,int h,int right,int top){
        LayoutParams p=new LayoutParams(dp(w),dp(h),Gravity.RIGHT|Gravity.TOP);
        p.setMargins(0,dp(top),dp(right),0);addView(view,p);
    }
    private void editBindings(){
        final String[] controls={"LUP","LDOWN","LLEFT","LRIGHT",
            "RUP","RDOWN","RLEFT","RRIGHT","LT","RT","A","B","X","Y",
            "LB","RB","L3","R3","DUP","DDOWN","DLEFT","DRIGHT","START","BACK"};
        final String[] keyNames={"W","A","S","D","↑","↓","←","→",
            "Space","Enter","Esc","Tab","Shift","Ctrl","E","Q","F","R","C",
            "1","2","3","4","بدون زر"};
        final int[] keyCodes={KeyEvent.KEYCODE_W,KeyEvent.KEYCODE_A,
            KeyEvent.KEYCODE_S,KeyEvent.KEYCODE_D,
            KeyEvent.KEYCODE_DPAD_UP,KeyEvent.KEYCODE_DPAD_DOWN,
            KeyEvent.KEYCODE_DPAD_LEFT,KeyEvent.KEYCODE_DPAD_RIGHT,
            KeyEvent.KEYCODE_SPACE,KeyEvent.KEYCODE_ENTER,
            KeyEvent.KEYCODE_ESCAPE,KeyEvent.KEYCODE_TAB,
            KeyEvent.KEYCODE_SHIFT_LEFT,KeyEvent.KEYCODE_CTRL_LEFT,
            KeyEvent.KEYCODE_E,KeyEvent.KEYCODE_Q,KeyEvent.KEYCODE_F,
            KeyEvent.KEYCODE_R,KeyEvent.KEYCODE_C,
            KeyEvent.KEYCODE_1,KeyEvent.KEYCODE_2,
            KeyEvent.KEYCODE_3,KeyEvent.KEYCODE_4,0};
        new AlertDialog.Builder(activity).setTitle("تخصيص الأزرار لهذه اللعبة")
            .setItems(controls,(dialog,which)->{
                String control=controls[which];
                new AlertDialog.Builder(activity)
                    .setTitle("زر "+control+" — اختر مفتاح اللعبة")
                    .setItems(keyNames,(d,index)->{
                        releaseAll();
                        prefs.edit().putInt("bind_"+control,keyCodes[index]).apply();
                    }).setNegativeButton("إلغاء",null).show();
            }).setNegativeButton("إلغاء",null).show();
    }
    private void resetBindings(){
        releaseAll();
        android.content.SharedPreferences.Editor edit=prefs.edit();
        for(String k:new String[]{"LUP","LDOWN","LLEFT","LRIGHT","RUP","RDOWN",
            "RLEFT","RRIGHT","LT","RT","A","B","X","Y","LB","RB","L3","R3",
            "DUP","DDOWN","DLEFT","DRIGHT","START","BACK"})
            edit.remove("bind_"+k);
        edit.apply();
    }
    private void menu(){
        String[] modes={"تلقائي: XInput وإلا كيبورد","XInput مباشر فقط","Keyboard فقط"};
        String[] options={"نمط الإدخال: "+modes[mode],
            "حجم الأزرار: "+size+"%","شفافية الأزرار: "+opacity+"%",
            editing?"حفظ مواقع الأزرار":"تحريك الأزرار",
            visible?"إخفاء الأزرار":"إظهار الأزرار",
            "تخصيص أزرار الكيبورد لهذه اللعبة","إعادة ترتيب الأزرار",
            "إعادة تعيين أزرار الكيبورد"};
        new AlertDialog.Builder(activity).setTitle("🎮 إعدادات التحكم")
          .setItems(options,(dialog,index)->{
            switch(index){
                case 0:
                    mode=(mode+1)%3;
                    prefs.edit().putInt("input",mode).apply();
                    releaseAll(); break;
                case 1:
                    size=size>=125?75:size+10;
                    prefs.edit().putInt("size",size).apply();
                    for(PadKey k:padKeys){
                        LayoutParams lp=(LayoutParams)k.getLayoutParams();
                        lp.width=dp(k.w*size/100f);lp.height=dp(k.h*size/100f);
                        k.setLayoutParams(lp);
                    }break;
                case 2:
                    opacity=opacity<=45?100:opacity-15;
                    prefs.edit().putInt("opacity",opacity).apply();
                    for(PadKey k:padKeys)k.setAlpha(opacity/100f);
                    break;
                case 3:
                    editing=!editing;releaseAll();
                    for(PadKey k:padKeys)k.invalidate();break;
                case 4:
                    visible=!visible;
                    if(!visible)releaseAll();
                    for(PadKey k:padKeys)k.setVisibility(visible?VISIBLE:GONE);
                    break;
                case 5:
                    editBindings();
                    break;
                case 6:
                    for(PadKey k:padKeys){
                        prefs.edit().remove("x_"+k.name).remove("y_"+k.name).apply();
                        LayoutParams lp=(LayoutParams)k.getLayoutParams();
                        lp.gravity=k.initialGravity;
                        lp.setMargins(dp(k.ml),dp(k.mt),dp(k.mr),dp(k.mb));
                        k.setLayoutParams(lp);
                    }break;
                case 7:
                    resetBindings();break;
            }
            settings.setText(editing?"✔ حفظ الترتيب":"⚙ تحكم");
        }).setNegativeButton("إغلاق",null).show();
    }
    public RM11UniversalPadV49039(Activity activity,
                                 RM11VirtualXInputV49037 xinput,KeySink keyboard,
                                 String gameId){
        super(activity);
        this.activity=activity;this.xinput=xinput;this.keyboard=keyboard;
        prefs=activity.getSharedPreferences("rm11_pad_profile_"+
            Integer.toHexString(gameId==null?0:gameId.hashCode()),0);
        mode=prefs.getInt("input",AUTO);
        size=prefs.getInt("size",100);
        opacity=prefs.getInt("opacity",85);
        setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        setClipChildren(false);setClipToPadding(false);
        setMotionEventSplittingEnabled(true);
        setFocusable(false);setClickable(false);
        // Wide-screen dark GameHub/Winlator-like controls, no opaque cover.
        add("LT",102,51,Gravity.LEFT|Gravity.TOP,26,25,0,0);
        add("LB",102,48,Gravity.LEFT|Gravity.TOP,26,88,0,0);
        add("L3",47,47,Gravity.LEFT|Gravity.TOP,30,155,0,0);
        add("RT",102,51,Gravity.RIGHT|Gravity.TOP,0,25,26,0);
        add("RB",102,48,Gravity.RIGHT|Gravity.TOP,0,88,26,0);
        add("R3",47,47,Gravity.RIGHT|Gravity.TOP,0,155,30,0);
        add("L",147,147,Gravity.LEFT|Gravity.BOTTOM,48,0,0,24);
        add("R",147,147,Gravity.RIGHT|Gravity.BOTTOM,0,0,216,24);
        add("DUP",53,53,Gravity.LEFT|Gravity.BOTTOM,220,0,0,122);
        add("DDOWN",53,53,Gravity.LEFT|Gravity.BOTTOM,220,0,0,17);
        add("DLEFT",53,53,Gravity.LEFT|Gravity.BOTTOM,168,0,0,70);
        add("DRIGHT",53,53,Gravity.LEFT|Gravity.BOTTOM,272,0,0,70);
        add("Y",58,58,Gravity.RIGHT|Gravity.BOTTOM,0,0,80,165);
        add("X",58,58,Gravity.RIGHT|Gravity.BOTTOM,0,0,140,105);
        add("B",58,58,Gravity.RIGHT|Gravity.BOTTOM,0,0,20,105);
        add("A",58,58,Gravity.RIGHT|Gravity.BOTTOM,0,0,80,45);
        add("BACK",85,43,Gravity.CENTER_HORIZONTAL|Gravity.BOTTOM,55,0,0,10);
        add("START",85,43,Gravity.CENTER_HORIZONTAL|Gravity.BOTTOM,0,0,55,10);
        settings=top("⚙ تحكم");
        settings.setOnClickListener(v->menu());
        topRight(settings,87,35,7,8);
        readout=top("XInput • فحص اللعبة");
        readout.setTextSize(10);
        LayoutParams info=new LayoutParams(dp(184),dp(30),
           Gravity.TOP|Gravity.CENTER_HORIZONTAL);
        info.topMargin=dp(5);
        addView(readout,info);
    }
    public int inputMode(){return mode;}
    public boolean useKeyboardFallback(){return mode==KEYBOARD || (mode==AUTO&&xinput.readCount()==0);}
    @Override protected void onAttachedToWindow(){
        super.onAttachedToWindow();post(poll);
    }
    @Override protected void onDetachedFromWindow(){
        removeCallbacks(poll);releaseAll();super.onDetachedFromWindow();
    }
    public void releaseAll(){
        for(PadKey k:padKeys)k.cancel();
        releaseKeyboard();
        gas=brake=0;xinput.releaseAll();
    }
}
