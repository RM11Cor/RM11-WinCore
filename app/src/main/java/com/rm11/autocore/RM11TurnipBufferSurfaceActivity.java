package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;

/**
 * Isolated opt-in display bridge: GPU writes 64-byte color via private Turnip,
 * Android CPU copies the verified word into ANativeWindow buffer. Not WSI.
 */
public final class RM11TurnipBufferSurfaceActivity extends Activity
        implements SurfaceHolder.Callback {
    private SurfaceView preview;
    private Button start,back;
    private TextView result;
    private boolean ready,running;
    private int width,height;
    @Override public void onCreate(Bundle savedState){
        super.onCreate(savedState);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xff111824);
        root.setPadding(18,15,18,15);
        TextView header=new TextView(this);
        header.setText("RM11 — PRIVATE Turnip GPU color → Android CPU Surface");
        header.setTextColor(Color.WHITE);
        header.setTextSize(18);
        root.addView(header);
        preview=new SurfaceView(this);
        preview.getHolder().addCallback(this);
        root.addView(preview,new LinearLayout.LayoutParams(-1,0,1));
        start=new Button(this);
        start.setText("Show 24 GPU-verified color frames on Android");
        start.setEnabled(false);
        start.setOnClickListener(v->runTest());
        root.addView(start);
        back=new Button(this);
        back.setText("Back — no game files changed");
        back.setOnClickListener(v->{if(!running)finish();});
        root.addView(back);
        ScrollView scroll=new ScrollView(this);
        result=new TextView(this);
        result.setTextColor(0xffc9e4ff);
        result.setTextIsSelectable(true);
        result.setTextSize(14);
        result.setText("This is a CPU BLIT of a GPU-produced color, NOT Vulkan WSI, "
                +"X11 or Wine. Wait for Surface, then tap test.");
        scroll.addView(result);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,-2));
        setContentView(root);
    }
    private void runTest(){
        if(running||!ready||width<=0||height<=0)return;
        Surface surface=preview.getHolder().getSurface();
        if(surface==null||!surface.isValid())return;
        running=true;start.setEnabled(false);back.setEnabled(false);
        result.setText("RM11_GPU_TO_ANDROID_SURFACE_V1\nTEST=RUNNING\n");
        Thread worker=new Thread(()->{
            String report;
            try{
                JSONObject r=RM11TurnipBufferSurface.run(
                        getApplicationContext(),surface,24);
                int frames=r.optInt("android_surface_posted_frames",0);
                int matches=r.optInt("gpu_readback_matches",0);
                boolean successful=r.optInt("vk_result",-999)==0 &&
                        frames==24 && matches==24 && r.optBoolean("any_surface_posted",false);
                report="RM11_GPU_TO_ANDROID_SURFACE_V1\n"
                      +"GPU_TO_ANDROID_STAGE="+r.optString("stage","UNKNOWN")
                      +"\nVK_RESULT="+r.optInt("vk_result",-999)
                      +"\nGPU_VENDOR_ID="+r.optLong("gpu_vendor_id",0)
                      +"\nGPU_DEVICE_ID="+r.optLong("gpu_device_id",0)
                      +"\nGPU_READBACK_MATCHES="+matches
                      +"\nANDROID_NATIVE_WINDOW_POSTED_FRAMES="+frames
                      +"\nANDROID_WINDOW_STATUS="+r.optInt("last_native_window_status",-999)
                      +"\nGPU_TO_ANDROID_CPU_BRIDGE="+(successful?"PASS":"NOT_PROVEN")
                      +"\nVISIBLE_COLORS_CONFIRMED=USER_REQUIRED"
                      +"\nNATIVE_VULKAN_SWAPCHAIN=NOT_PROVEN"
                      +"\nWINE_DXVK_GAME_FRAMES=NOT_TESTED"
                      +"\nENGINE_ACTIVATION=DISABLED";
            }catch(Throwable error){
                report="RM11_GPU_TO_ANDROID_SURFACE_V1\n"
                      +"GPU_TO_ANDROID_CPU_BRIDGE=ERROR\n"
                      +"ERROR_TYPE="+error.getClass().getSimpleName()
                      +"\nNATIVE_VULKAN_SWAPCHAIN=NOT_PROVEN"
                      +"\nWINE_DXVK_GAME_FRAMES=NOT_TESTED"
                      +"\nENGINE_ACTIVATION=DISABLED";
            }
            final String display=report;
            runOnUiThread(()->{
                if(isDestroyed())return;
                result.setText(display);
                running=false;back.setEnabled(true);start.setEnabled(ready);
            });
        },"rm11-private-turnip-buffer-surface");
        worker.setDaemon(true);worker.start();
    }
    @Override public void surfaceCreated(SurfaceHolder holder){
        ready=holder.getSurface()!=null&&holder.getSurface().isValid();
        if(start!=null)start.setEnabled(ready&&!running);
    }
    @Override public void surfaceChanged(SurfaceHolder holder,int format,int w,int h){
        width=w;height=h;ready=(w>0&&h>0);
        if(start!=null)start.setEnabled(ready&&!running);
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder){
        ready=false;if(start!=null)start.setEnabled(false);
    }
}
