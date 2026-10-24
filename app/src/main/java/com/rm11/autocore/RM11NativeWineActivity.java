package com.rm11.autocore;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import com.rm11.autocore.diagnostics.OfflineDiagnosticArchive;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.NativeX11TcpBridge;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import com.termux.x11.MainActivity;
import com.termux.x11.RM11NativeX11Service;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * v4 PREVIEW: real X.Org LorieView surface, not legacy Java ScreenView.
 * Start X.Org in a dedicated Android service process and relay the unchanged
 * Wine DISPLAY TCP port to its private AF_UNIX X socket.
 *
 * This version remains a device preview: a successful CI APK build is not
 * proof of readable glyphs or a working Wine desktop on REDMAGIC.
 */
public final class RM11NativeWineActivity extends MainActivity {
    private static final int EXPORT_DIAGNOSTICS=9400;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService wineWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService exportWorker=Executors.newSingleThreadExecutor();
    private NativeX11TcpBridge relay;
    private WineAutoDesktopRunner.Session session;
    private String finalReport="";
    private volatile String lastStatus="جاري بدء خادم X.Org الأصلي...";
    private boolean shuttingDown;
    private boolean wineStarted;
    private boolean nativeServiceRequested;
    private final Runnable nativeReadiness=new Runnable() {
        private int attempts;
        @Override public void run() {
            if(shuttingDown || isFinishing())return;
            if(getLorieView()!=null && getLorieView().connected()
                    && getLorieView().getWidth()>0 && getLorieView().getHeight()>0) {
                wineStarted=true;
                final int w=getLorieView().getWidth();
                final int h=getLorieView().getHeight();
                wineWorker.execute(()->launchWhenX11Ready(w,h));
                return;
            }
            if(++attempts<120)ui.postDelayed(this,600);
            else {
                lastStatus="لم يكتمل اتصال شاشة Lorie بخادم X.Org خلال مهلة البدء.";
                OfflineDiagnosticJournal.record(RM11NativeWineActivity.this,
                        "v4-native-start-failure",lastStatus);
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if(isFinishing())return;
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        installPreviewControls();
        try {
            File tmp=new File(getFilesDir(),RM11NativeX11Service.TMPDIR_NAME);
            if(!tmp.isDirectory() && !tmp.mkdirs())
                throw new IOException("Cannot create native private TMPDIR");
            relay=new NativeX11TcpBridge();
            relay.start(tmp);
            nativeServiceRequested=true;
            startService(new Intent(this,RM11NativeX11Service.class));
            lastStatus="خادم X.Org الأصلي طُلب؛ جاري انتظار عرض Lorie...";
            ui.postDelayed(nativeReadiness,350);
        } catch(Exception e) {
            lastStatus="RM11_V4_NATIVE_START_FAILED: "+e;
            OfflineDiagnosticJournal.record(this,"v4-native-start-failure",lastStatus);
            Toast.makeText(this,"تعذر تشغيل X.Org؛ افتح التشخيص.",Toast.LENGTH_LONG).show();
        }
    }

    private void installPreviewControls() {
        LinearLayout controls=new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        Button diagnose=new Button(this);
        diagnose.setText("التشخيص والسجلات");
        diagnose.setTextSize(11);
        diagnose.setAllCaps(false);
        diagnose.setOnClickListener(v->openDiagnostics());
        Button legacy=new Button(this);
        legacy.setText("الواجهة السابقة");
        legacy.setTextSize(11);
        legacy.setAllCaps(false);
        legacy.setOnClickListener(v->{
            startActivity(new Intent(this,EmbeddedX11Activity.class));
            finish();
        });
        controls.addView(diagnose);
        controls.addView(legacy);
        FrameLayout.LayoutParams p=new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP|Gravity.START);
        addContentView(controls,p);
    }

    private void launchWhenX11Ready(int w,int h) {
        WineX11EndpointProbe.Result probe=null;
        for(int i=0;i<36 && !shuttingDown;i++) {
            probe=WineX11EndpointProbe.probeEmbeddedDisplay2();
            if(probe.accepted)break;
            try{Thread.sleep(500);}catch(InterruptedException e){
                Thread.currentThread().interrupt();
                return;
            }
        }
        if(shuttingDown)return;
        if(probe==null || !probe.accepted) {
            lastStatus="RM11_V4_NATIVE_X11_PROTOCOL_NOT_READY";
            finalReport=lastStatus+"\n"
                    +(relay==null?"RELAY_MISSING":relay.diagnostics());
            OfflineDiagnosticJournal.record(this,"v4-native-x11-connect",finalReport);
            return;
        }
        OfflineDiagnosticJournal.record(this,"v4-native-x11-connect",
                "RM11_V4_NATIVE_X11_HANDSHAKE_ACCEPTED\n"
                +(relay==null?"RELAY_MISSING":relay.diagnostics())
                +"RM11_V4_DISPLAY_GLYPHS_NOT_YET_VERIFIED\n");
        WineAutoDesktopRunner.Session current=new WineAutoDesktopRunner.Session();
        session=current;
        lastStatus="X.Org متصل؛ جاري تشغيل Wine...";
        finalReport=WineAutoDesktopRunner.run(this,current,
                value->lastStatus=value,w,h);
        OfflineDiagnosticJournal.record(this,"v4-native-wine-session",finalReport);
        lastStatus="انتهت جلسة Wine؛ راجع التشخيص للتحقق.";
    }

    private void openDiagnostics() {
        String live=session!=null?session.diagnostics():finalReport;
        if(live==null || live.trim().isEmpty())live="لم يبدأ Wine بعد.";
        String details="RM11_V4_NATIVE_XORG_PREVIEW\n"
                +"native service requested: "+nativeServiceRequested+"\n"
                +"Wine launch requested: "+wineStarted+"\n"
                +"Lorie display connected: "+(getLorieView()!=null && getLorieView().connected())+"\n"
                +"X.Org via TCP relay: "+(relay==null?"NOT_STARTED":relay.diagnostics())+"\n"
                +"Windows text visible: NOT VERIFIED BY CI\n"
                +"Status: "+lastStatus+"\n\n"+live;
        OfflineDiagnosticJournal.record(this,"v4-native-live",details);
        TextView txt=new TextView(this);
        txt.setText(details);
        txt.setTextIsSelectable(true);
        txt.setTextSize(12);
        txt.setTextColor(Color.WHITE);
        txt.setPadding(22,16,22,16);
        ScrollView panel=new ScrollView(this);
        panel.setBackgroundColor(0xFF122033);
        panel.addView(txt);
        new AlertDialog.Builder(this)
                .setTitle("RM11 v4 | X.Org + Wine")
                .setView(panel)
                .setPositiveButton("حفظ ZIP",(d,w)->exportZip())
                .setNegativeButton("الرجوع",(d,w)->{})
                .show();
    }

    private void exportZip() {
        Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("application/zip");
        save.putExtra(Intent.EXTRA_TITLE,"RM11-v4-Native-X11-Diagnostics.zip");
        startActivityForResult(save,EXPORT_DIAGNOSTICS);
    }

    @Override protected void onActivityResult(int code,int result,Intent data) {
        super.onActivityResult(code,result,data);
        if(code!=EXPORT_DIAGNOSTICS || result!=RESULT_OK || data==null
                || data.getData()==null)return;
        Uri dest=data.getData();
        exportWorker.execute(()->{
            try(OutputStream out=getContentResolver().openOutputStream(dest)) {
                if(out==null)throw new IOException("ZIP target unavailable");
                OfflineDiagnosticArchive.export(this,out);
                runOnUiThread(()->Toast.makeText(this,
                        "تم حفظ تقرير v4",Toast.LENGTH_LONG).show());
            }catch(Exception e){
                runOnUiThread(()->Toast.makeText(this,
                        "فشل حفظ ZIP: "+e.getClass().getSimpleName(),
                        Toast.LENGTH_LONG).show());
            }
        });
    }

    @Override protected void onDestroy() {
        shuttingDown=true;
        ui.removeCallbacks(nativeReadiness);
        if(session!=null)session.close();
        if(relay!=null)relay.close();
        if(nativeServiceRequested)stopService(new Intent(this,RM11NativeX11Service.class));
        wineWorker.shutdownNow();
        exportWorker.shutdown();
        super.onDestroy();
    }
}
