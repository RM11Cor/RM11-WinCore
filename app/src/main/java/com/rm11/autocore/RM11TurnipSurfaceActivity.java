package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import com.rm11.autocore.runtime.KernixEngineQualificationV49090;

/** Explicit opt-in test in isolated :rm11_graphics_probe Android process.
 * If WSI is unavailable, report exact stage instead of using system Vulkan.
 */
public final class RM11TurnipSurfaceActivity extends Activity
        implements SurfaceHolder.Callback {
    private SurfaceView preview;
    private TextView result;
    private Button start, back;
    private boolean ready, running;
    private int width, height;
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(0xff111824);
        getWindow().setNavigationBarColor(0xff111824);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(18,18,18,18);
        root.setBackgroundColor(0xff111824);
        TextView title=new TextView(this);
        title.setText("RM11 PRIVATE Turnip → Android Surface (no Wine)");
        title.setTextSize(17);
        title.setTextColor(Color.WHITE);
        root.addView(title);
        preview=new SurfaceView(this);
        preview.getHolder().addCallback(this);
        root.addView(preview,new LinearLayout.LayoutParams(-1,0,1f));
        start=new Button(this);
        start.setText("Render 60 moving frames using private Turnip only");
        start.setEnabled(false);
        start.setOnClickListener(v->runProbe());
        root.addView(start);
        back=new Button(this);
        back.setText("Back — no game files changed");
        back.setOnClickListener(v->{if(!running)finish();});
        root.addView(back);
        result=new TextView(this);
        result.setTextSize(14);
        result.setTextColor(0xffc4e1fa);
        result.setTextIsSelectable(true);
        result.setText("Wait for Surface. Colors must visibly change in preview.\n"
                +"No system Vulkan fallback. Wine/DXVK remains disabled.");
        root.addView(result,new LinearLayout.LayoutParams(-1,-2));
        setContentView(root);
    }

    private void runProbe(){
        if(running||!ready||width<=0||height<=0)return;
        Surface surface=preview.getHolder().getSurface();
        if(surface==null||!surface.isValid())return;
        KernixEngineQualificationV49090.recordProbeAttempt(
            getApplicationContext(),"NATIVE_VULKAN_WSI_PRESENT",
            "RUNNING","NATIVE_WSI_SURFACE_STARTED");
        running=true;
        start.setEnabled(false);
        back.setEnabled(false);
        result.setText("PRIVATE_TURNIP_WSI_PROBE=STARTED\n");
        new Thread(()->{
            String output;
            try {
                JSONObject r=RM11PrivateTurnipSurface.run(
                        getApplicationContext(),surface,60);
                boolean receipt=KernixEngineQualificationV49090
                    .recordNativeWsi(getApplicationContext(),r);
                KernixEngineQualificationV49090.recordProbeAttempt(
                    getApplicationContext(),"NATIVE_VULKAN_WSI_PRESENT",
                    receipt?"PASS":"FAIL",r.optString("stage","NATIVE_UNKNOWN"));
                int frames=r.optInt("frames",0);
                boolean complete=r.optBoolean("success",false)&&frames==60;
                output="PRIVATE_TURNIP_WSI_STAGE="+r.optString("stage","UNKNOWN")
                      +"\nPRIVATE_TURNIP_WSI_VK_RESULT="+r.optInt("vkResult",-999)
                      +"\nPRIVATE_TURNIP_WSI_FRAMES_PRESENTED="+frames
                      +"\nPRIVATE_TURNIP_WSI_EXTENT="+r.optInt("width",0)
                      +"x"+r.optInt("height",0)
                      +"\nPRIVATE_TURNIP_WSI_QUEUE_PRESENT="
                      +(complete?"PASS":"NOT_PROVEN")
                      +"\nKERNIX_ENGINE_WSI_RECEIPT="+
                         (receipt?"RECORDED":"NOT_RECORDED")
                      +"\nPRIVATE_TURNIP_ANDROID_PIXELS_VISUALLY_CONFIRMED=USER_REQUIRED"
                      +"\nWINE_DXVK_GAME_FRAMES=NOT_TESTED"
                      +"\nENGINE_ACTIVATION=DISABLED";
            }catch(Throwable error) {
                String reason=error.getClass().getSimpleName();
                KernixEngineQualificationV49090.recordProbeAttempt(
                    getApplicationContext(),"NATIVE_VULKAN_WSI_PRESENT",
                    "FAIL",reason);
                output="PRIVATE_TURNIP_WSI_PROBE=EXCEPTION "+reason
                      +"\nPRIVATE_TURNIP_WSI_QUEUE_PRESENT=NOT_PROVEN"
                      +"\nWINE_DXVK_GAME_FRAMES=NOT_TESTED"
                      +"\nENGINE_ACTIVATION=DISABLED";
            }
            String display=output;
            runOnUiThread(()->{
                if(isDestroyed())return;
                result.setText(display);
                running=false;
                back.setEnabled(true);
                start.setEnabled(ready);
            });
        },"rm11-private-turnip-wsi-test").start();
    }

    @Override public void surfaceCreated(SurfaceHolder holder){
        ready=holder.getSurface()!=null&&holder.getSurface().isValid();
        start.setEnabled(ready&&!running);
    }
    @Override public void surfaceChanged(SurfaceHolder holder,int format,int w,int h){
        width=w;height=h;ready=w>0&&h>0;
        start.setEnabled(ready&&!running);
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder){
        ready=false;
        start.setEnabled(false);
    }
}
