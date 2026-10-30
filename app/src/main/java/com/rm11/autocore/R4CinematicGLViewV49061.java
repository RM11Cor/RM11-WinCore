package com.rm11.autocore;

import android.content.Context;
import android.graphics.PixelFormat;
import android.opengl.GLES20;
import android.opengl.GLSurfaceView;
import android.opengl.Matrix;
import android.os.SystemClock;
import android.view.View;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.util.ArrayList;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

/**
 * REAL GPU vertex-rendered 3D worlds. Each theme has independent geometry.
 * Scenes draw behind normal Android launcher buttons; no effect on Wine X11.
 * 25fps cap, pause when not visible, vertex budget <50k, no textures/network.
 * The preview's photorealistic environments are reference art, not faked here.
 */
public final class R4CinematicGLViewV49061 extends GLSurfaceView {
    private boolean active;
    private final boolean animated;
    private final Runnable frame=new Runnable(){
        @Override public void run(){
            if(!active||!isShown()||!animated)return;
            requestRender();
            postDelayed(this,40);
        }
    };
    public R4CinematicGLViewV49061(Context ctx,int profile){
        super(ctx);
        animated=RM11UiThemesV49059.motion(ctx);
        setEGLContextClientVersion(2);
        setEGLConfigChooser(8,8,8,8,16,0);
        setRenderer(new WorldRenderer(profile,animated));
        setRenderMode(GLSurfaceView.RENDERMODE_WHEN_DIRTY);
        setPreserveEGLContextOnPause(false);
    }
    public void start(){
        super.onResume();active=true;requestRender();
        if(animated){removeCallbacks(frame);postDelayed(frame,40);}
    }
    public void stop(){
        active=false;removeCallbacks(frame);
        super.onPause();
    }
    @Override protected void onDetachedFromWindow(){
        active=false;removeCallbacks(frame);
        super.onDetachedFromWindow();
    }
    private static final class WorldRenderer implements GLSurfaceView.Renderer {
        private final int profile;private final boolean animate;
        private FloatBuffer vertices,orbital;private int n,orbitN,program,aPos,aColor,uMatrix;
        private final float[] projection=new float[16],camera=new float[16];
        private final float[] model=new float[16],viewModel=new float[16],mvp=new float[16];
        private long start;
        WorldRenderer(int theme,boolean motion){profile=RM11UiThemesV49059.clamp(theme);animate=motion;}
        private int shader(int kind,String src){
            int s=GLES20.glCreateShader(kind);
            GLES20.glShaderSource(s,src);GLES20.glCompileShader(s);
            int[] ok=new int[1];GLES20.glGetShaderiv(s,GLES20.GL_COMPILE_STATUS,ok,0);
            if(ok[0]==0)throw new IllegalStateException("GL shader build failed");
            return s;
        }
        @Override public void onSurfaceCreated(GL10 unused,EGLConfig cfg){
            String vs="attribute vec3 aPosition;attribute vec3 aColor;varying vec3 vColor;uniform mat4 uMVP;void main(){vColor=aColor;gl_Position=uMVP*vec4(aPosition,1.0);}";
            String fs="precision mediump float;varying vec3 vColor;void main(){gl_FragColor=vec4(vColor,1.0);}";
            int v=shader(GLES20.GL_VERTEX_SHADER,vs),f=shader(GLES20.GL_FRAGMENT_SHADER,fs);
            program=GLES20.glCreateProgram();GLES20.glAttachShader(program,v);GLES20.glAttachShader(program,f);
            GLES20.glLinkProgram(program);GLES20.glDeleteShader(v);GLES20.glDeleteShader(f);
            aPos=GLES20.glGetAttribLocation(program,"aPosition");
            aColor=GLES20.glGetAttribLocation(program,"aColor");
            uMatrix=GLES20.glGetUniformLocation(program,"uMVP");
            SceneBuilder b=new SceneBuilder();
            build(b,profile);
            vertices=b.buffer();n=b.count();
            SceneBuilder orb=new SceneBuilder();addOrbit(orb,profile);
            orbital=orb.buffer();orbitN=orb.count();
            GLES20.glEnable(GLES20.GL_DEPTH_TEST);
            GLES20.glDisable(GLES20.GL_CULL_FACE);
            start=SystemClock.uptimeMillis();
        }
        @Override public void onSurfaceChanged(GL10 unused,int w,int h){
            GLES20.glViewport(0,0,w,h);
            Matrix.perspectiveM(projection,0,56f,Math.max(.1f,w/(float)Math.max(1,h)),.1f,90f);
        }
        private void draw(FloatBuffer data,int count,float[] transform){
            if(data==null||count==0)return;
            GLES20.glUniformMatrix4fv(uMatrix,1,false,transform,0);
            data.position(0);GLES20.glVertexAttribPointer(aPos,3,GLES20.GL_FLOAT,false,24,data);
            data.position(3);GLES20.glVertexAttribPointer(aColor,3,GLES20.GL_FLOAT,false,24,data);
            GLES20.glEnableVertexAttribArray(aPos);GLES20.glEnableVertexAttribArray(aColor);
            GLES20.glDrawArrays(GLES20.GL_TRIANGLES,0,count);
        }
        @Override public void onDrawFrame(GL10 unused){
            final float[][] bg={{.005f,.021f,.066f},{.09f,.005f,.018f},
                {.09f,.043f,.024f},{.02f,.09f,.072f},{.016f,.011f,.086f},{.018f,.023f,.058f}};
            float[] c=bg[profile];
            GLES20.glClearColor(c[0],c[1],c[2],1f);
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT|GLES20.GL_DEPTH_BUFFER_BIT);
            GLES20.glUseProgram(program);
            float time=animate?(SystemClock.uptimeMillis()-start)/1000f:0f;
            float x=(float)Math.sin(time*.19f)*.75f;
            float y=(float)Math.sin(time*.26f)*.18f;
            Matrix.setLookAtM(camera,0,x,3.6f+y,13.4f,0,1.2f,-6.5f,0,1,0);
            Matrix.setIdentityM(model,0);
            Matrix.rotateM(model,0,(float)Math.sin(time*.10f)*1.6f,0,1,0);
            Matrix.multiplyMM(viewModel,0,camera,0,model,0);
            Matrix.multiplyMM(mvp,0,projection,0,viewModel,0);
            draw(vertices,n,mvp);
            Matrix.setIdentityM(model,0);
            Matrix.rotateM(model,0,time*21f,0,1,0);
            Matrix.multiplyMM(viewModel,0,camera,0,model,0);
            Matrix.multiplyMM(mvp,0,projection,0,viewModel,0);
            draw(orbital,orbitN,mvp);
        }
        private static void addOrbit(SceneBuilder b,int t){
            int rgb=new int[]{0x26caff,0xff4b64,0xffc67d,0x8bffbb,0x987bff,0x39dfff}[t];
            float r=t==4?4.6f:t==2?3.2f:2.35f;
            float y=t==4?2.4f:3.0f,z=t==4?-10f:-9.8f;
            for(int i=0;i<120;i++){
                float a=i*(float)Math.PI/60f,bb=(i+1)*(float)Math.PI/60f;
                float x1=(float)Math.cos(a)*r,x2=(float)Math.cos(bb)*r;
                float yy1=y+(float)Math.sin(a)*r*.6f,yy2=y+(float)Math.sin(bb)*r*.6f;
                b.quad(x1,yy1,z,x2,yy2,z,x2,yy2+.06f,z,x1,yy1+.06f,z,rgb);
            }
        }
        private static void build(SceneBuilder b,int t){
            int floor=new int[]{0x071831,0x291018,0x493622,0x184136,0x181747,0x22283f}[t];
            b.box(0,-2,-9,40,.2f,49,floor);
            int trim=new int[]{0x168ed1,0xbc243d,0xc48d4d,0x4ebd8d,0x7963f5,0x419fdc}[t];
            for(int n=-13;n<=13;n+=2){
                b.box(n,-1.86f,-8,.014f,.02f,40,trim);
                b.box(0,-1.86f,-9+n,30,.015f,.018f,trim);
            }
            if(t==0){ // neon city, varied real 3D buildings
                for(int i=0;i<48;i++){
                    int side=i%2==0?-1:1;
                    float x=side*(4+(i%6)*2.2f),z=-19+(i/6)*3.5f;
                    float h=2+(i*13%10)*.9f;
                    b.box(x,h/2-2,z,1.45f,h,1.5f,i%3==0?0x112f51:0x0e1b39);
                    b.box(x,h-1.9f,z,1.55f,.12f,1.6f,i%3==0?0x1fa6e8:0x8e32e8);
                    for(int j=0;j<7;j++){
                        b.box(x,h*.15f+j*.38f-1.8f,z+.78f,1.15f,.06f,.04f,i%2==0?0x2bc7f9:0xbf6bff);
                    }
                }
            }else if(t==1){ // combat hangar
                for(int s=-1;s<=1;s+=2)for(int i=0;i<8;i++){
                    float x=s*(5+i*2f);
                    b.box(x,2.8f,-12,1.1f,9,10,i%2==0?0x4b101e:0x24121f);
                    b.box(x,7.2f,-12,1.35f,.25f,11,0xe4314c);
                }
                b.box(0,-1.6f,-7,7,.4f,9,0x5c252c);
                b.box(0,-1.32f,-7,5,.1f,6,0xc23643);
            }else if(t==2){ // golden hall & raised gallery
                for(int s=-1;s<=1;s+=2)for(int i=0;i<7;i++){
                    float x=s*(6+(i%2)*2.4f),z=-20+i*2.8f;
                    b.box(x,2,z,1.25f,8,1.15f,0x795936);
                    b.box(x,6,z,2,.35f,1.7f,0xe3b06b);
                }
                b.box(0,-1.55f,-8,11,.75f,8,0x6e4736);
                for(int i=-2;i<=2;i++){
                    b.box(i*2.2f,-.5f,-8,1.8f,1.1f,1.8f,0xa47b42);
                    b.box(i*2.2f,.9f,-8,1.3f,1.9f,.18f,i%2==0?0x4c8996:0x7d384a);
                }
            }else if(t==3){ // growing 3D trees and rolling hills
                for(int i=0;i<95;i++){
                    float x=((i*73)%57-28)*.8f,z=-2-((i*31)%58)*.65f;
                    b.box(x,-.8f,z,.13f,2,.14f,0x6d4432);
                    float sz=1.4f+(i%6)*.16f;
                    b.pyramid(x,1.1f,z,.9f,sz,i%2==0?0x1c8e64:0x348a5f);
                }
                for(int j=0;j<11;j++)b.pyramid((j-5)*3,1.5f,-24,3,5+(j%4),0x506d73);
            }else if(t==4){ // orbital planet with 3D rings
                b.sphere(3,2.2f,-12,3.2f,0x3458bb);
                for(int i=0;i<8;i++)
                    b.box(-8+i*2.3f,-.2f,-7,.5f,2.1f,.13f,i%2==0?0x4250bb:0x198bca);
            }else{ // immersive PC gaming studio, screens and tower
                b.box(0,4,-18,23,13,.5f,0x233149);
                b.box(0,-1.2f,-5,12,.7f,5,0x41344d);
                b.box(0,1.6f,-10,6,4.1f,.7f,0x080f21);
                b.box(0,1.6f,-9.6f,5.4f,3.5f,.12f,0x126eae);
                b.box(-5,.3f,-6,2.5f,4,2.5f,0x1b1f32);
                for(int i=0;i<3;i++)b.box(-5,-.7f+i*1.1f,-4.69f,1,.25f,.06f,i==0?0x43caff:i==1?0xa66cff:0xff668e);
                b.box(5,4.5f,-17.6f,6.5f,5,.12f,0xc16799);
                for(int i=0;i<18;i++)b.box(-3.1f+i*.36f,4.2f+(i%7)*.2f,-17.5f,.19f,1.5f+(i%5)*.35f,.12f,0x303b67);
            }
        }
    }
    private static final class SceneBuilder{
        private final ArrayList<Float> a=new ArrayList<>();
        private void vertex(float x,float y,float z,int color){
            a.add(x);a.add(y);a.add(z);a.add(((color>>16)&255)/255f);
            a.add(((color>>8)&255)/255f);a.add((color&255)/255f);
        }
        private void tri(float[] p,float[] q,float[] r,int c){
            vertex(p[0],p[1],p[2],c);vertex(q[0],q[1],q[2],c);vertex(r[0],r[1],r[2],c);
        }
        private void quad(float ax,float ay,float az,float bx,float by,float bz,
                          float cx,float cy,float cz,float dx,float dy,float dz,int c){
            float[] a={ax,ay,az},b={bx,by,bz},cc={cx,cy,cz},d={dx,dy,dz};
            tri(a,b,cc,c);tri(a,cc,d,c);
        }
        void box(float x,float y,float z,float w,float h,float depth,int color){
            float a=x-w/2,b=x+w/2,lo=y-h/2,hi=y+h/2,
                near=z+depth/2,far=z-depth/2;
            quad(a,lo,near,b,lo,near,b,hi,near,a,hi,near,color);
            quad(b,lo,far,a,lo,far,a,hi,far,b,hi,far,darken(color,.59f));
            quad(a,hi,near,b,hi,near,b,hi,far,a,hi,far,darken(color,1.12f));
            quad(a,lo,far,b,lo,far,b,lo,near,a,lo,near,darken(color,.68f));
            quad(a,lo,far,a,lo,near,a,hi,near,a,hi,far,darken(color,.74f));
            quad(b,lo,near,b,lo,far,b,hi,far,b,hi,near,darken(color,.86f));
        }
        void pyramid(float x,float y,float z,float r,float h,int color){
            float[] p={x,y+h,z};
            tri(new float[]{x-r,y,z-r},new float[]{x+r,y,z-r},p,color);
            tri(new float[]{x+r,y,z-r},new float[]{x+r,y,z+r},p,darken(color,.82f));
            tri(new float[]{x+r,y,z+r},new float[]{x-r,y,z+r},p,darken(color,.7f));
            tri(new float[]{x-r,y,z+r},new float[]{x-r,y,z-r},p,darken(color,.91f));
        }
        void sphere(float x,float y,float z,float r,int color){
            int lat=12,lon=20;
            for(int i=0;i<lat;i++)for(int j=0;j<lon;j++){
                double a=i*Math.PI/lat,b=(i+1)*Math.PI/lat,
                  u=j*Math.PI*2/lon,v=(j+1)*Math.PI*2/lon;
                float[] p0=sph(x,y,z,r,a,u),p1=sph(x,y,z,r,b,u),
                  p2=sph(x,y,z,r,b,v),p3=sph(x,y,z,r,a,v);
                tri(p0,p1,p2,darken(color,.55f+(float)Math.cos(a)*.2f+.4f));
                tri(p0,p2,p3,darken(color,.55f+(float)Math.cos(a)*.2f+.4f));
            }
        }
        private float[] sph(float x,float y,float z,float r,double a,double b){
            return new float[]{x+r*(float)(Math.sin(a)*Math.cos(b)),
                y+r*(float)Math.cos(a),z+r*(float)(Math.sin(a)*Math.sin(b))};
        }
        static int darken(int color,float f){
            int r=Math.min(255,Math.max(0,Math.round((color>>16&255)*f)));
            int g=Math.min(255,Math.max(0,Math.round((color>>8&255)*f)));
            int b=Math.min(255,Math.max(0,Math.round((color&255)*f)));
            return r<<16|g<<8|b;
        }
        FloatBuffer buffer(){
            ByteBuffer bb=ByteBuffer.allocateDirect(a.size()*4).order(ByteOrder.nativeOrder());
            FloatBuffer out=bb.asFloatBuffer();
            for(Float v:a)out.put(v);out.position(0);return out;
        }
        int count(){return a.size()/6;}
    }
}