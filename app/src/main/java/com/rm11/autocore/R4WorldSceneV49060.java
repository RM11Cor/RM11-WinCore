package com.rm11.autocore;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.os.SystemClock;
import android.view.View;

/**
 * Six genuine procedural scene compositions, not a shared wallpaper palette:
 * neon city / red hangar / golden exhibition hall / mountain valley /
 * holographic orbital chamber / gaming studio. Background is decorative,
 * game and icon controls live in Android Views above it.
 *
 * No native render engine or Wine process. UI drawing pauses when hidden.
 */
public final class R4WorldSceneV49060 extends View {
    private final int scene;
    private final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);
    private long epoch;
    private boolean moving,active;
    private float phase;
    private final boolean thumbnail;
    public R4WorldSceneV49060(Context context,int theme){
        this(context,theme,false);
    }
    public R4WorldSceneV49060(Context context,int theme,boolean thumbnail){
        super(context);scene=RM11UiThemesV49059.clamp(theme);
        this.thumbnail=thumbnail;
        moving=!thumbnail && RM11UiThemesV49059.motion(context);
        setClickable(false);
    }
    @Override protected void onAttachedToWindow(){
        super.onAttachedToWindow();active=true;epoch=SystemClock.uptimeMillis();
        if(moving)postInvalidateDelayed(45);
    }
    @Override protected void onDetachedFromWindow(){
        active=false;super.onDetachedFromWindow();
    }
    @Override protected void onWindowVisibilityChanged(int visibility){
        super.onWindowVisibilityChanged(visibility);
        active=visibility==VISIBLE&&isAttachedToWindow();
        if(active&&moving)postInvalidateDelayed(45);
    }
    private void paint(int color){p.reset();p.setAntiAlias(true);p.setColor(color);}
    private void rect(Canvas c,float l,float t,float r,float b,int color){
        paint(color);c.drawRect(l,t,r,b,p);
    }
    private void round(Canvas c,float l,float t,float r,float b,float rad,int color){
        paint(color);c.drawRoundRect(l,t,r,b,rad,rad,p);
    }
    private void line(Canvas c,float x,float y,float xx,float yy,int col,float thick){
        paint(col);p.setStrokeWidth(thick);c.drawLine(x,y,xx,yy,p);
    }
    private void circle(Canvas c,float x,float y,float radius,int color){
        paint(color);c.drawCircle(x,y,radius,p);
    }
    private void ellipse(Canvas c,float l,float t,float r,float b,int color,float stroke){
        paint(color);p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(stroke);
        c.drawOval(new RectF(l,t,r,b),p);p.setStyle(Paint.Style.FILL);
    }
    private void gradient(Canvas c,int top,int middle,int bottom){
        p.reset();p.setShader(new LinearGradient(0,0,0,600,
            new int[]{top,middle,bottom},new float[]{0,.57f,1},Shader.TileMode.CLAMP));
        // Canvas transformed to logical 1000 x 600.
        c.drawRect(0,0,1000,600,p);p.setShader(null);
    }
    private void glow(Canvas c,float x,float y,float r,int rgb,int alpha){
        paint(Color.WHITE);
        // Alpha fades to transparent around the center.
        p.setShader(new RadialGradient(x,y,r,
            new int[]{(Math.min(255,alpha)&255)<<24|(rgb&0xffffff),rgb&0x00ffffff},
            null,Shader.TileMode.CLAMP));
        c.drawCircle(x,y,r,p);p.setShader(null);
    }
    private void polygon(Canvas c,int color,float... xy){
        paint(color);Path path=new Path();path.moveTo(xy[0],xy[1]);
        for(int i=2;i+1<xy.length;i+=2)path.lineTo(xy[i],xy[i+1]);
        path.close();c.drawPath(path,p);
    }
    private void city(Canvas c){
        gradient(c,0xff061b36,0xff09213f,0xff070a15);
        glow(c,530,140,310,0xff087fff,145);
        glow(c,840,210,270,0xffab23ff,80);
        // Moving skyline layers; "windows" are spatially unique, not a recolor.
        for(int i=0;i<26;i++){
            float x=i*46-40+(i%3)*9, h=120+((i*47)%230);
            boolean near=i%3==0;
            rect(c,x,380-h,x+40,396,near?0xff0d1830:0xff122744);
            rect(c,x+5,380-h-15,x+30,380-h,0xff182641);
            for(int y=(int)(390-h);y<375;y+=20)
              for(int wx=7;wx<39;wx+=14)
                if((wx+y+i)%4!=0)round(c,x+wx,y,x+wx+4,y+8,1,
                    i%2==0?0xff1888a9:0xffba2e9a);
        }
        polygon(c,0xff10162b,0,405,1000,405,1000,600,0,600);
        float sweep=(phase*170)%200;
        for(int i=0;i<13;i++){
            float yy=405+i*i*1.4f;
            line(c,0,yy,1000,yy,i%3==0?0x663ad9ff:0x343c86c9,1);
        }
        for(int i=-7;i<=7;i++){
            float x=500+i*110;
            line(c,500,405,x,600,0x443ac7ff,1.3f);
        }
        line(c,0,420+sweep,1000,420+sweep,0x7721c7f4,2);
    }
    private void hangar(Canvas c){
        gradient(c,0xff180811,0xff35101c,0xff090910);
        glow(c,510,230,340,0xffff1739,145);
        polygon(c,0xff151019,0,0,200,0,370,600,0,600);
        polygon(c,0xff1c1018,800,0,1000,0,1000,600,630,600);
        for(int i=0;i<6;i++){
            int x=i*200;
            line(c,x,0,500,340,0x99cb2340,5);
            line(c,x,600,500,344,0x66ad1437,6);
        }
        polygon(c,0xff170e17,0,390,1000,390,1000,600,0,600);
        for(int i=0;i<12;i++){
            int y=395+i*20;
            line(c,0,y,1000,y,0x552f1625,2);
        }
        float x=450+(float)Math.sin(phase*6.28)*28;
        circle(c,x,250,34,0xff10151c);
        polygon(c,0xff10151d,x-50,284,x+54,284,x+78,405,x-84,405);
        line(c,x-51,286,x-81,406,0xffbc1e3e,4);
        line(c,x+53,286,x+78,406,0xffbc1e3e,4);
        for(int i=0;i<25;i++){
            float a=i*1.24f+phase*8f;
            float xx=(i*101)%1000;
            float yy=(i*83+phase*160)%600;
            round(c,xx,yy,xx+2,yy+7,1,0x88ff5533);
        }
    }
    private void gallery(Canvas c){
        gradient(c,0xff201224,0xff49301f,0xff130e13);
        glow(c,500,170,340,0xffffa343,135);
        polygon(c,0xff452d28,0,0,1000,0,820,365,170,365);
        for(int i=0;i<6;i++){
            int x=i*194;
            rect(c,x,28,x+22,405,0xff3b2728);
            round(c,x+2,28,x+10,382,2,0xff85542a);
            ellipse(c,x+31,15,x+139,115,0x88ffbf52,4);
        }
        polygon(c,0xff241a20,0,380,1000,380,1000,600,0,600);
        for(int j=0;j<6;j++){
            float x=j*200;
            line(c,500,382,x,600,0x558d5b32,2);
        }
        float s=(float)Math.sin(phase*6.28)*6;
        ellipse(c,180,440+s,820,560+s,0x99ffc266,10);
        ellipse(c,240,455+s,760,535+s,0x88d9a666,5);
        glow(c,500,480+s,210,0xffffbd64,110);
        for(int i=0;i<4;i++){
            float x=230+i*148, height=185+(i==1?27:0);
            rect(c,x,182+s,x+95,182+height+s,0xff090f20);
            line(c,x,182+s,x+95,182+s,0x99ffe3a4,3);
            line(c,x,182+height+s,x+95,182+height+s,0x99ffe3a4,3);
        }
    }
    private void nature(Canvas c){
        gradient(c,0xff96bfe2,0xff508aa6,0xff173b34);
        glow(c,740,118,150,0xffffe3a6,150);
        polygon(c,0xff4d808d,0,350,135,180,255,310,410,116,600,325,820,165,1000,332,1000,600,0,600);
        polygon(c,0xff366e69,0,390,150,310,280,380,430,255,560,389,850,286,1000,378,1000,600,0,600);
        polygon(c,0xffddf0ed,350,185,410,116,450,186,405,178);
        polygon(c,0xffd5ebf2,776,215,820,165,866,218,820,208);
        polygon(c,0xff264c3f,0,470,210,355,395,475,630,345,820,463,1000,365,1000,600,0,600);
        polygon(c,0xff1f4e59,190,478,800,478,1000,600,0,600);
        for(int i=0;i<14;i++){
            float x=i*81, y=400+(i%4)*22;
            line(c,x,y,x,y-70,0xff214a38,8);
            circle(c,x,y-78,28+(i%3)*8,0xff183e35);
            circle(c,x+10,y-88,18,0xff337449);
        }
        for(int i=0;i<15;i++){
            float y=480+i*7;
            line(c,200,y,820,y,0x446fd5cf,1);
        }
    }
    private void cosmos(Canvas c){
        gradient(c,0xff0b1038,0xff1c1144,0xff050b20);
        glow(c,490,280,330,0xff3853ff,110);
        for(int i=0;i<70;i++){
            int x=(i*131+57)%1000,y=(i*173+19)%590;
            circle(c,x,y,i%5==0?2.2f:1.1f,0xaaddffff);
        }
        float drift=(float)Math.sin(phase*6.28);
        glow(c,515,244,165,0xff187eff,140);
        circle(c,515,244+drift*7,129,0xff0d4c98);
        paint(0xdd19a7ff);
        p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(3.4f);
        for(int i=0;i<8;i++){
            float delta=i*12;
            c.drawArc(new RectF(405+delta,135+delta,625-delta,356-delta),
                (phase*90+i*33)%360,95,false,p);
        }
        p.setStyle(Paint.Style.FILL);
        for(int i=0;i<4;i++){
            c.save();c.rotate(-21+i*12,515,260);
            ellipse(c,285-i*9,195+i*8,740+i*9,335-i*8,
                (i%2==0?0xaa52b8ff:0x88a669ff),3);
            c.restore();
        }
        polygon(c,0xff0b1631,0,530,1000,530,1000,600,0,600);
        for(int i=0;i<8;i++){
            float y=533+i*10;
            line(c,0,y,1000,y,0x555c8fff,1.5f);
        }
    }
    private void desktop(Canvas c){
        gradient(c,0xff111633,0xff352244,0xff120e21);
        glow(c,750,170,360,0xffb32bff,100);
        // Window, city beyond glass, multiple PC monitors and RGB desk.
        rect(c,120,45,880,392,0xff151b32);
        rect(c,129,52,871,383,0xff593862);
        rect(c,145,66,855,367,0xff472e5b);
        glow(c,525,195,210,0xfff47b4d,60);
        for(int i=0;i<21;i++){
            int x=160+i*34, height=(i*71)%165+42;
            rect(c,x,345-height,x+22,345,0xff252342);
            for(int y=355-height;y<345;y+=19)rect(c,x+7,y,x+10,y+4,0xffef85b8);
        }
        line(c,500,52,500,383,0xff152039,16);
        polygon(c,0xff14101c,0,460,1000,460,1000,600,0,600);
        for(int i=0;i<3;i++){
            float x=190+i*210;
            round(c,x,300,x+193,466,11,0xff080e20);
            round(c,x+8,310,x+185,443,8,0xff1f3269);
            glow(c,x+98,373,89,i==1?0xffa349ef:0xff1888ff,100);
            line(c,x+96,465,x+96,490,0xff53618c,11);
            line(c,x+55,490,x+139,490,0xff6e7bac,7);
        }
        rect(c,0,495,1000,514,0xff17162a);
        for(int i=0;i<13;i++){
            int x=i*81+(int)((phase*65)%30);
            line(c,x,510,x+45,510,i%2==0?0xff4f8afa:0xffac49ed,3);
        }
    }
    @Override protected void onDraw(Canvas actual){
        super.onDraw(actual);
        float width=getWidth(),height=getHeight();
        if(width<=0||height<=0)return;
        if(moving)phase=(SystemClock.uptimeMillis()-epoch)%26000/26000f;
        else phase=.25f;
        actual.save();
        // Center-crop logical scene for portrait; do not horizontally stretch.
        float scale=Math.max(width/1000f,height/600f);
        actual.translate((width-scale*1000f)/2f,(height-scale*600f)/2f);
        actual.scale(scale,scale);
        switch(scene){
            case 1:hangar(actual);break;
            case 2:gallery(actual);break;
            case 3:nature(actual);break;
            case 4:cosmos(actual);break;
            case 5:desktop(actual);break;
            default:city(actual);break;
        }
        // Lighting and dark readability veil; full scene remains visible.
        paint(0x63020710);actual.drawRect(0,0,1000,600,p);
        actual.restore();
        if(moving&&active)postInvalidateDelayed(45); // <=22 FPS scene; cards animate independently.
    }
}
