package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import au.com.darkside.xserver.XServer;
import com.rm11.autocore.diagnostics.OfflineDiagnosticArchive;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * v3.0.3: RM11's home screen IS its genuine embedded Wine X11 desktop.
 *
 * No "choose test EXE", no status/footer banner, no synthetic screenshot,
 * no external Android XSDL app. Signed Wine Explorer and original winefile
 * auto-launch into the app-owned XServer surface. The only Android overlay
 * is the diagnostics/logs control.
 */
public final class EmbeddedX11Activity extends Activity {
    private static final int EXPORT_ZIP = 9303;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private XServer xserver;
    private volatile WineAutoDesktopRunner.Session session;
    private volatile String finalReport="";
    private volatile String lastStatus="جاري تهيئة سطح مكتب Windows...";
    private boolean started;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setStatusBarColor(Color.BLACK);
        getWindow().setNavigationBarColor(Color.BLACK);

        FrameLayout frame=new FrameLayout(this);
        frame.setBackgroundColor(0xFF1A2030);
        xserver=new XServer(this,WineX11EndpointProbe.EMBEDDED_PORT,null);
        xserver.setAccessControl(true);
        xserver.getAccessControlHosts().add(0x7f000001);
        View screen=xserver.getScreen();
        frame.addView(screen,new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT));
        Button diagnose=new Button(this);
        diagnose.setText("التشخيص والسجلات");
        diagnose.setTextSize(13);
        diagnose.setAllCaps(false);
        diagnose.setAlpha(0.91f);
        diagnose.setOnClickListener(v->openDiagnostics());
        FrameLayout.LayoutParams corner=new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.END);
        int margin=(int)(getResources().getDisplayMetrics().density*8);
        corner.setMargins(margin,margin,margin,margin);
        frame.addView(diagnose,corner);
        setContentView(frame);
        // Native ScreenView owns its X11 socket only after layout. Do not
        // start Wine until the real Android graphics surface has a size.
        screen.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
            @Override public void onLayoutChange(View view,int left,int top,int right,
                    int bottom,int oldLeft,int oldTop,int oldRight,int oldBottom) {
                if(!started && right>left && bottom>top) {
                    started=true;
                    view.removeOnLayoutChangeListener(this);
                    launchDesktop();
                }
            }
        });
    }

    private void launchDesktop() {
        WineAutoDesktopRunner.Session current=new WineAutoDesktopRunner.Session();
        session=current;
        worker.execute(()->{
            finalReport=WineAutoDesktopRunner.run(this,current,
                    message->runOnUiThread(()->lastStatus=message));
            OfflineDiagnosticJournal.record(this,"wine-auto-desktop-v303",finalReport);
            runOnUiThread(()->{
                lastStatus=finalReport.contains("RM11_V303_DESKTOP_START_ERROR")
                        ? "فشل بدء Wine. افتح التشخيص للاطلاع على التفاصيل."
                        : "انتهت جلسة Wine. افتح التشخيص لقراءة السجلات.";
            });
        });
    }

    private void openDiagnostics() {
        WineAutoDesktopRunner.Session current=session;
        String report=current!=null ? current.diagnostics() : finalReport;
        if(report==null||report.trim().isEmpty())report="لا يوجد سجل بعد.";
        // Save the running-session snapshot so exporting the ZIP includes
        // useful live evidence even if the Windows desktop stays foreground.
        OfflineDiagnosticJournal.record(this,"wine-live-desktop-v303",report);
        TextView log=new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(11);
        log.setTextColor(0xFFEEEEEE);
        log.setPadding(24,20,24,20);
        log.setText(lastStatus+"\n\n"+report);
        ScrollView scroll=new ScrollView(this);
        scroll.setBackgroundColor(0xFF152033);
        scroll.addView(log);
        AlertDialog dialog=new AlertDialog.Builder(this)
                .setTitle("RM11 | التشخيص والسجلات")
                .setView(scroll)
                .setPositiveButton("حفظ تقرير ZIP",(d,w)->exportDiagnostics())
                .setNegativeButton("الرجوع للواجهة",(d,w)->{})
                .create();
        dialog.show();
        WindowManager.LayoutParams attrs=dialog.getWindow().getAttributes();
        attrs.width=(int)(getResources().getDisplayMetrics().widthPixels*0.87f);
        attrs.height=(int)(getResources().getDisplayMetrics().heightPixels*0.82f);
        dialog.getWindow().setAttributes(attrs);
    }

    private void exportDiagnostics() {
        Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("application/zip");
        save.putExtra(Intent.EXTRA_TITLE,"RM11-Desktop-Diagnostics-v3.0.3.zip");
        try{startActivityForResult(save,EXPORT_ZIP);}
        catch(Exception e){Toast.makeText(this,"تعذر فتح حفظ التقرير",Toast.LENGTH_LONG).show();}
    }

    @Override protected void onActivityResult(int req,int result,Intent data) {
        super.onActivityResult(req,result,data);
        if(req!=EXPORT_ZIP || result!=RESULT_OK || data==null || data.getData()==null)
            return;
        android.net.Uri target=data.getData();
        worker.execute(()->{
            try(OutputStream out=getContentResolver().openOutputStream(target)) {
                if(out==null)throw new java.io.IOException("No output stream");
                OfflineDiagnosticArchive.export(this,out);
                runOnUiThread(()->Toast.makeText(this,
                        "تم حفظ تقرير Wine ZIP",Toast.LENGTH_LONG).show());
            } catch(Exception e) {
                runOnUiThread(()->Toast.makeText(this,
                        "فشل حفظ التقرير: "+e.getClass().getSimpleName(),
                        Toast.LENGTH_LONG).show());
            }
        });
    }

    @Override protected void onDestroy() {
        WineAutoDesktopRunner.Session active=session;
        if(active!=null)active.close();
        if(xserver!=null)xserver.stop();
        worker.shutdownNow();
        super.onDestroy();
    }
}
