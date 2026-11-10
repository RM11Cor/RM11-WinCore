package com.r4.fh5probe;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class MainActivity extends Activity {
    private static final int REQUEST_ZIP=2020;
    private static final int MAX_ENTRY=16*1024*1024;
    private static final int MAX_TOTAL=24*1024*1024;
    private static native String nativeProbe();
    private static native String nativeUploadSwatch(byte[] data);
    static { System.loadLibrary("fh5probe"); }
    private TextView output;
    private Button inspect, openZip;

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView scroll=new ScrollView(this);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int p=(int)(18*getResources().getDisplayMetrics().density);
        root.setPadding(p,p,p,p);
        scroll.addView(root);
        TextView header=new TextView(this);
        header.setText("FH5 Native Port — M20\nReal Forza texture GPU upload\n\nResearch diagnostic, NOT the game");
        header.setTextSize(19);
        header.setTypeface(null,Typeface.BOLD);
        header.setTextColor(Color.rgb(24,35,55));
        root.addView(header);
        inspect=new Button(this);
        inspect.setText("1 — Inspect Vulkan capabilities");
        root.addView(inspect,new LinearLayout.LayoutParams(-1,-2));
        openZip=new Button(this);
        openZip.setText("2 — Select FH5_SWATCH_M12.zip and upload");
        root.addView(openZip,new LinearLayout.LayoutParams(-1,-2));
        output=new TextView(this);
        output.setTextSize(15);
        output.setTextIsSelectable(true);
        output.setPadding(0,p,0,p);
        output.setText("Select the ZIP containing your three extracted .swatchbin samples. No Steam or internet required.\n\nM20 tests GPU transfer; it does not render a 3D model.");
        root.addView(output);
        inspect.setOnClickListener(v->runInspection());
        openZip.setOnClickListener(v->{
            Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i,REQUEST_ZIP);
        });
        setContentView(scroll);
    }
    private void setBusy(boolean busy) {
        inspect.setEnabled(!busy);
        openZip.setEnabled(!busy);
    }
    private void runInspection() {
        setBusy(true);
        output.setText("Inspecting Vulkan GPU...");
        new Thread(()->{
            String r;
            try { r=nativeProbe(); }
            catch(Throwable e){r="Probe failed: "+e.toString();}
            final String result=r;
            runOnUiThread(()->{if(!isFinishing()) {output.setText(result);setBusy(false);}});
        },"fh5-m20-probe").start();
    }
    @Override protected void onActivityResult(int request,int code,Intent data) {
        super.onActivityResult(request,code,data);
        if(request!=REQUEST_ZIP || code!=RESULT_OK || data==null || data.getData()==null) return;
        Uri uri=data.getData();
        setBusy(true);
        output.setText("Reading ZIP safely and testing native Vulkan uploads...");
        new Thread(()->{
            String result;
            try { result=processZip(uri); }
            catch(Throwable e) {result="M20 upload failed: "+e.toString();}
            final String text=result;
            runOnUiThread(()->{if(!isFinishing()) {output.setText(text);setBusy(false);}});
        },"fh5-m20-zip-upload").start();
    }
    private String processZip(Uri uri) throws Exception {
        StringBuilder log=new StringBuilder("FH5 M20 — real swatch GPU transfer\n");
        int count=0,scanned=0,total=0,successful=0;
        byte[] buffer=new byte[32768];
        try(InputStream stream=getContentResolver().openInputStream(uri)) {
            if(stream==null) throw new IllegalStateException("Unable to open selected file");
            try(ZipInputStream zip=new ZipInputStream(stream)) {
                ZipEntry e;
                while((e=zip.getNextEntry())!=null) {
                    if(++scanned>100) throw new IllegalArgumentException("Too many entries in ZIP");
                    if(e.isDirectory()||!e.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".swatchbin")){
                        zip.closeEntry();
                        continue;
                    }
                    if(count>=12) throw new IllegalArgumentException("Too many swatches for diagnostic");
                    ByteArrayOutputStream b=new ByteArrayOutputStream();
                    int n;
                    while((n=zip.read(buffer))!=-1) {
                        if(b.size()+n>MAX_ENTRY || total+b.size()+n>MAX_TOTAL)
                            throw new IllegalArgumentException("Texture archive exceeds size limits");
                        b.write(buffer,0,n);
                    }
                    byte[] bytes=b.toByteArray();
                    total+=bytes.length;
                    count++;
                    String name=e.getName();
                    int slash=Math.max(name.lastIndexOf('/'),name.lastIndexOf('\\'));
                    if(slash>=0) name=name.substring(slash+1);
                    log.append("\n").append(name).append(" (").append(bytes.length).append(" B)\n");
                    String status=nativeUploadSwatch(bytes);
                    log.append(status).append("\n");
                    if(status.startsWith("PASS:")) successful++;
                    zip.closeEntry();
                }
            }
        }
        log.append("\nRESULT: ").append(successful).append("/").append(count).append(" textures uploaded successfully.");
        if(count==0) log.append("\nNo .swatchbin files found. Choose FH5_SWATCH_M12.zip.");
        log.append("\n\nGPU copy + image view + sampler tests only. No visible Vulkan render or FH5 gameplay.");
        return log.toString();
    }
}
