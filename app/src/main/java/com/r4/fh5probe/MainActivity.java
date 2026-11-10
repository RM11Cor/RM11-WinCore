package com.r4.fh5probe;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.net.Uri;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.ImageView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class MainActivity extends Activity {
    private static final int REQUEST_ZIP=2020;
    private static final int REQUEST_RENDER=2021;
    private static final int REQUEST_MESH=2022;
    private static final int MAX_ENTRY=16*1024*1024;
    private static final int MAX_TOTAL=24*1024*1024;
    private static native String nativeProbe();
    private static native String nativeUploadSwatch(byte[] data);
    private static native int[] nativeRenderSwatch(byte[] data);
    private static native int[] nativeRenderMesh(byte[] data,float radians,float elevation,float zoom);
    static { System.loadLibrary("fh5probe"); }
    private TextView output;
    private Button inspect, openZip, renderZip, openMesh, rotateLeft, rotateRight, tiltLower, tiltHigher, zoomIn, zoomOut;
    private ImageView meshImage;
    private TextView meshLabel;
    private byte[] meshData;
    private float meshAngle=0.95f;
    private float meshPitch=0.36f;
    private float meshZoom=1.0f;
    private LinearLayout previews;

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView scroll=new ScrollView(this);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int p=(int)(18*getResources().getDisplayMetrics().density);
        root.setPadding(p,p,p,p);
        scroll.addView(root);
        TextView header=new TextView(this);
        header.setText("FH5 Native Port — M23\nVulkan 3D camera + lighting\n\nResearch diagnostic, NOT the game");
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
        renderZip=new Button(this);
        renderZip.setText("3 — Render FH5 swatches with Vulkan");
        root.addView(renderZip,new LinearLayout.LayoutParams(-1,-2));
        output=new TextView(this);
        output.setTextSize(15);
        output.setTextIsSelectable(true);
        output.setPadding(0,p,0,p);
        output.setText("Select the ZIP containing your three extracted .swatchbin samples. No Steam or internet required.\n\nM20 tests GPU transfer; it does not render a 3D model.");
        root.addView(output);
        previews=new LinearLayout(this);
        previews.setOrientation(LinearLayout.VERTICAL);
        root.addView(previews);
        TextView meshSection=new TextView(this);
        meshSection.setText("\nM23 — Real FH5 car-body perspective viewer");
        meshSection.setTextSize(17);
        meshSection.setTypeface(null,Typeface.BOLD);
        root.addView(meshSection);
        openMesh=new Button(this);
        openMesh.setText("4 — Select FH5_M22_Geometry_Staging.zip");
        root.addView(openMesh,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout rotations=new LinearLayout(this);
        rotations.setOrientation(LinearLayout.HORIZONTAL);
        rotateLeft=new Button(this);
        rotateLeft.setText("◀ Rotate");
        rotateRight=new Button(this);
        rotateRight.setText("Rotate ▶");
        rotations.addView(rotateLeft,new LinearLayout.LayoutParams(0,-2,1));
        rotations.addView(rotateRight,new LinearLayout.LayoutParams(0,-2,1));
        root.addView(rotations);
        LinearLayout cameraAngles=new LinearLayout(this);
        cameraAngles.setOrientation(LinearLayout.HORIZONTAL);
        tiltLower=new Button(this);
        tiltLower.setText("Camera lower");
        tiltHigher=new Button(this);
        tiltHigher.setText("Camera higher");
        cameraAngles.addView(tiltLower,new LinearLayout.LayoutParams(0,-2,1));
        cameraAngles.addView(tiltHigher,new LinearLayout.LayoutParams(0,-2,1));
        root.addView(cameraAngles);
        LinearLayout zoomControls=new LinearLayout(this);
        zoomControls.setOrientation(LinearLayout.HORIZONTAL);
        zoomOut=new Button(this);
        zoomOut.setText("Zoom −");
        zoomIn=new Button(this);
        zoomIn.setText("Zoom +");
        zoomControls.addView(zoomOut,new LinearLayout.LayoutParams(0,-2,1));
        zoomControls.addView(zoomIn,new LinearLayout.LayoutParams(0,-2,1));
        root.addView(zoomControls);
        meshLabel=new TextView(this);
        meshLabel.setText("Choose the M22 geometry ZIP. A Vulkan 3D image will appear here.");
        meshLabel.setTextSize(15);
        root.addView(meshLabel);
        meshImage=new ImageView(this);
        meshImage.setAdjustViewBounds(true);
        meshImage.setScaleType(ImageView.ScaleType.FIT_CENTER);
        root.addView(meshImage,new LinearLayout.LayoutParams(-1,-2));
        inspect.setOnClickListener(v->runInspection());
        openZip.setOnClickListener(v->{
            Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i,REQUEST_ZIP);
        });
        renderZip.setOnClickListener(v->{
            Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i,REQUEST_RENDER);
        });
        openMesh.setOnClickListener(v->{
            Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivityForResult(i,REQUEST_MESH);
        });
        rotateLeft.setOnClickListener(v->{
            if(meshData!=null){meshAngle-=0.42f;renderMeshAsync();}
        });
        rotateRight.setOnClickListener(v->{
            if(meshData!=null){meshAngle+=0.42f;renderMeshAsync();}
        });
        tiltLower.setOnClickListener(v->{
            if(meshData!=null){meshPitch=Math.max(0.10f,meshPitch-0.12f);renderMeshAsync();}
        });
        tiltHigher.setOnClickListener(v->{
            if(meshData!=null){meshPitch=Math.min(1.22f,meshPitch+0.12f);renderMeshAsync();}
        });
        zoomOut.setOnClickListener(v->{
            if(meshData!=null){meshZoom=Math.max(0.70f,meshZoom-0.10f);renderMeshAsync();}
        });
        zoomIn.setOnClickListener(v->{
            if(meshData!=null){meshZoom=Math.min(1.45f,meshZoom+0.10f);renderMeshAsync();}
        });
        setContentView(scroll);
    }
    private void setBusy(boolean busy) {
        inspect.setEnabled(!busy);
        openZip.setEnabled(!busy);
        renderZip.setEnabled(!busy);
        openMesh.setEnabled(!busy);
        rotateLeft.setEnabled(!busy && meshData!=null);
        rotateRight.setEnabled(!busy && meshData!=null);
        tiltLower.setEnabled(!busy && meshData!=null);
        tiltHigher.setEnabled(!busy && meshData!=null);
        zoomIn.setEnabled(!busy && meshData!=null);
        zoomOut.setEnabled(!busy && meshData!=null);
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
    private byte[] readBounded(InputStream stream,int maximum) throws Exception {
        ByteArrayOutputStream result=new ByteArrayOutputStream();
        byte[] buffer=new byte[16384];
        int n;
        while((n=stream.read(buffer))!=-1) {
            if(result.size()+n>maximum) throw new IllegalArgumentException("FHMS file too large");
            result.write(buffer,0,n);
        }
        return result.toByteArray();
    }
    private byte[] loadMesh(Uri uri) throws Exception {
        try(InputStream raw=getContentResolver().openInputStream(uri)) {
            if(raw==null) throw new IllegalStateException("Cannot open selected mesh");
            java.io.BufferedInputStream stream=new java.io.BufferedInputStream(raw);
            stream.mark(4);
            byte[] signature=new byte[4];
            int n=stream.read(signature);
            stream.reset();
            if(n>=2 && signature[0]=='P' && signature[1]=='K') {
                int scanned=0;
                try(ZipInputStream zip=new ZipInputStream(stream)) {
                    ZipEntry entry;
                    while((entry=zip.getNextEntry())!=null) {
                        if(++scanned>100)throw new IllegalArgumentException("ZIP has too many entries");
                        if(!entry.isDirectory() && entry.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".fhmesh")) {
                            byte[] data=readBounded(zip,16*1024*1024);
                            zip.closeEntry();
                            return data;
                        }
                        zip.closeEntry();
                    }
                }
                throw new IllegalArgumentException("No .fhmesh inside ZIP");
            }
            return readBounded(stream,16*1024*1024);
        }
    }
    private void renderMeshAsync() {
        if(meshData==null)return;
        setBusy(true);
        meshLabel.setText("Rendering 17 parts with real Vulkan indexed triangles...");
        final byte[] source=meshData;
        final float rotation=meshAngle;
        final float elevation=meshPitch;
        final float zoom=meshZoom;
        new Thread(()->{
            try {
                int[] pixels=nativeRenderMesh(source,rotation,elevation,zoom);
                if(pixels==null||pixels.length<3)throw new IllegalStateException("No GPU readback");
                int w=pixels[0],h=pixels[1];
                if(w<=0||h<=0||longPixelCount(w,h)!=pixels.length-2)
                    throw new IllegalStateException("Invalid Vulkan framebuffer");
                Bitmap bitmap=Bitmap.createBitmap(w,h,Bitmap.Config.ARGB_8888);
                bitmap.setPixels(pixels,2,w,0,0,w,h);
                runOnUiThread(()->{
                    if(isFinishing())return;
                    meshImage.setImageBitmap(bitmap);
                    meshLabel.setText("PASS: FHMS 3D mesh rendered by Vulkan" +
                        "\\nYaw "+String.format(java.util.Locale.ROOT,"%.2f",rotation)+
                        " | elevation "+String.format(java.util.Locale.ROOT,"%.2f",elevation)+
                        " | zoom "+String.format(java.util.Locale.ROOT,"%.2f",zoom)+
                        "\\nZ-up camera, test lighting and colors. Not the final FH5 graphics.");
                    setBusy(false);
                });
            }catch(Throwable problem) {
                final String error=problem.toString();
                runOnUiThread(()->{
                    if(isFinishing())return;
                    meshLabel.setText("M22 Vulkan render failed: "+error);
                    setBusy(false);
                });
            }
        },"fh5-m22-indexed-render").start();
    }
    private static long longPixelCount(int w,int h){return (long)w*h;}
    @Override protected void onActivityResult(int request,int code,Intent data) {
        super.onActivityResult(request,code,data);
        if(request==REQUEST_MESH) {
            if(code!=RESULT_OK||data==null||data.getData()==null)return;
            final Uri uri=data.getData();
            setBusy(true);
            meshLabel.setText("Reading FHMS geometry from selected ZIP...");
            new Thread(()->{
                try {
                    byte[] loaded=loadMesh(uri);
                    runOnUiThread(()->{
                        if(isFinishing())return;
                        meshData=loaded;renderMeshAsync();
                    });
                }catch(Throwable e){
                    final String error=e.toString();
                    runOnUiThread(()->{
                        if(isFinishing())return;
                        meshLabel.setText("FHMS import failed: "+error);
                        setBusy(false);
                    });
                }
            },"fh5-m22-import").start();
            return;
        }
        if((request!=REQUEST_ZIP && request!=REQUEST_RENDER) || code!=RESULT_OK || data==null || data.getData()==null) return;
        final boolean render=request==REQUEST_RENDER;
        previews.removeAllViews();
        Uri uri=data.getData();
        setBusy(true);
        output.setText(render ? "Running Vulkan texture shaders on GPU..." : "Reading ZIP and uploading to Vulkan...");
        new Thread(()->{
            String result;
            try { result=processZip(uri,render); }
            catch(Throwable e) {result="FH5 Vulkan test failed: "+e.toString();}
            final String text=result;
            runOnUiThread(()->{if(!isFinishing()) {output.setText(text);setBusy(false);}});
        },"fh5-m21-vulkan-render").start();
    }
    private String processZip(Uri uri,boolean render) throws Exception {
        StringBuilder log=new StringBuilder(render ? "FH5 M21 — Vulkan fragment shader rendering\n" : "FH5 M20 — real swatch GPU transfer\n");
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
                    if(render) {
                        try {
                            int[] pixels=nativeRenderSwatch(bytes);
                            if(pixels==null || pixels.length<3) throw new IllegalStateException("No rendered pixels");
                            int width=pixels[0],height=pixels[1];
                            if(width<=0||height<=0||pixels.length!=width*height+2)
                                throw new IllegalStateException("Invalid Vulkan readback dimensions");
                            Bitmap bitmap=Bitmap.createBitmap(width,height,Bitmap.Config.ARGB_8888);
                            bitmap.setPixels(pixels,2,width,0,0,width,height);
                            boolean variable=false;
                            for(int k=3;k<pixels.length;k++) if(pixels[k]!=pixels[2]) {variable=true;break;}
                            final String label=name+"  ("+width+"×"+height+")";
                            runOnUiThread(()->{
                                if(isFinishing())return;
                                TextView caption=new TextView(this);
                                caption.setText(label);
                                caption.setTextSize(16);
                                caption.setPadding(0,20,0,8);
                                previews.addView(caption);
                                ImageView picture=new ImageView(this);
                                picture.setAdjustViewBounds(true);
                                picture.setImageBitmap(bitmap);
                                picture.setScaleType(ImageView.ScaleType.FIT_CENTER);
                                previews.addView(picture,new LinearLayout.LayoutParams(-1,-2));
                            });
                            log.append("PASS: Vulkan fragment shader sampled texture and GPU pixels read back\n");
                            if(!variable) log.append("WARNING: uniform pixel result — inspect preview for rendering issue\n");
                            successful++;
                        } catch(Throwable error) {
                            log.append("FAIL: ").append(error).append("\n");
                        }
                    } else {
                        String status=nativeUploadSwatch(bytes);
                        log.append(status).append("\n");
                        if(status.startsWith("PASS:")) successful++;
                    }
                    zip.closeEntry();
                }
            }
        }
        log.append("\nRESULT: ").append(successful).append("/").append(count)
           .append(render ? " textures rendered by Vulkan shader." : " textures uploaded successfully.");
        if(count==0) log.append("\nNo .swatchbin files found. Choose FH5_SWATCH_M12.zip.");
        log.append(render ? "\nOffscreen Vulkan GPU render; pixels displayed by Android ImageView. Not 3D car rendering or FH5 gameplay." : "\nGPU upload only. Not gameplay.");
        return log.toString();
    }
}
