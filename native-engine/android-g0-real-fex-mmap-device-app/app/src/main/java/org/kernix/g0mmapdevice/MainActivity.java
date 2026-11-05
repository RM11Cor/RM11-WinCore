package org.kernix.g0mmapdevice;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Opt-in, standalone original-FEX x86 anonymous guest mmap/munmap proof.
 * No storage access, guest file chooser, root, full glibc or Wine. */
public final class MainActivity extends Activity {
    private static final String RUNNER="libkernix_g0_original_fex_owned_vm.so";
    private static final String CORE="libFEXCore.so";
    private static final String START="KERNIX_G0_ACTUAL_ORIGINAL_FEX_X86_MMAP_MUNMAP_GUEST_START";
    private static final String MMAP="KERNIX_G0_REAL_FEX_X86_GUEST_MMAP_ALLOCATED_CANONICAL_RW_PAGE";
    private static final String STORE="KERNIX_G0_REAL_FEX_X86_GUEST_BYTE_5A_STORED_AND_NATIVE_PAGE_UNMAPPED";
    private static final String SUCCESS="KERNIX_G0_ANDROID_REAL_ORIGINAL_FEX_GUEST_MMAP_STORE_LOAD_MUNMAP_NATIVE_PASS_NO_LDSO_GLIBC";
    private static final String HOST16K="G0_X86_GUEST_4K_MMAP_ON_16K_HOST_PAGE_DENIED_SAFELY=1";
    private static final int MAX_LOG=24576;
    private final AtomicBoolean running=new AtomicBoolean(false);
    private Button go;
    private TextView result;

    private static String hex(byte[] hash) {
        StringBuilder sb=new StringBuilder(64);
        for(byte b:hash) {
            sb.append(Character.forDigit((b>>4)&15,16));
            sb.append(Character.forDigit(b&15,16));
        }
        return sb.toString();
    }
    private static String shaFile(Path path)throws Exception {
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(path)) {
            byte[] buf=new byte[8192];int n;
            while((n=in.read(buf))>=0)if(n>0)md.update(buf,0,n);
        }
        return hex(md.digest());
    }
    private String signedAssetHash(String name)throws Exception {
        byte[] bytes;
        try(InputStream in=getAssets().open(name)) { bytes=in.readAllBytes(); }
        if(bytes.length!=65 || bytes[64]!='\n')
            throw new IOException("G0_MMAP_BAD_SIGNED_ASSET_DIGEST");
        String expected=new String(bytes,0,64,StandardCharsets.US_ASCII);
        if(!expected.matches("[0-9a-f]{64}"))
            throw new IOException("G0_MMAP_BAD_SHA256_ENCODING");
        return expected;
    }
    private Path verifiedNative(Path libs,String file,String digestAsset)throws Exception {
        Path p=libs.resolve(file).normalize();
        if(!p.getParent().equals(libs) ||
           Files.isSymbolicLink(p) ||
           !Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS) ||
           !p.toRealPath().getParent().equals(libs) ||
           !shaFile(p).equals(signedAssetHash(digestAsset)))
            throw new IOException("G0_MMAP_NATIVE_SHA256_OR_PATH_REJECTED_"+file);
        return p;
    }
    private static int exactMarkerCount(String log,String marker) {
        int count=0;
        for(String line:log.split("\\R")) if(marker.equals(line))count++;
        return count;
    }
    private String execute()throws Exception {
        Path libs=new File(getApplicationInfo().nativeLibraryDir).toPath().toRealPath();
        Path binary=verifiedNative(libs,RUNNER,"original-fex-owned-vm-runner.sha256");
        verifiedNative(libs,CORE,"original-fexcore.sha256");
        if(!Files.isExecutable(binary))
            return "G0_ANDROID_GUEST_MMAP_PASS=0\nG0_NATIVE_CHILD_NOT_EXECUTABLE=1";
        ProcessBuilder pb=new ProcessBuilder(binary.toString());
        pb.directory(getFilesDir());
        pb.environment().clear();
        pb.environment().put("LD_LIBRARY_PATH",libs.toString());
        pb.redirectErrorStream(true);
        Process child=pb.start();
        ByteArrayOutputStream captured=new ByteArrayOutputStream();
        AtomicBoolean overLimit=new AtomicBoolean(false);
        Thread reader=new Thread(()->{
            try(InputStream in=child.getInputStream()){
                byte[] buf=new byte[512];int n;
                while((n=in.read(buf))!=-1){
                    if(captured.size()+n>MAX_LOG){
                        overLimit.set(true);child.destroyForcibly();break;
                    }
                    captured.write(buf,0,n);
                }
            }catch(Exception e){overLimit.set(true);child.destroyForcibly();}
        },"g0-mmap-output");
        reader.start();
        try {
            boolean finished=child.waitFor(24,TimeUnit.SECONDS);
            if(!finished)child.destroyForcibly();
            reader.join(1800);
            if(reader.isAlive()){
                child.destroyForcibly();reader.interrupt();reader.join(600);
            }
            if(!finished)return "G0_ANDROID_GUEST_MMAP_PASS=0\nG0_CHILD_WATCHDOG_TIMEOUT=1";
            if(overLimit.get()||reader.isAlive())
                return "G0_ANDROID_GUEST_MMAP_PASS=0\nG0_CHILD_OUTPUT_LIMIT_REJECTED=1";
            int rc=child.exitValue();
            String log=new String(captured.toByteArray(),StandardCharsets.UTF_8);
            if(rc==24 && exactMarkerCount(log,HOST16K)==1)
                return "G0_ANDROID_GUEST_MMAP_PASS=0\n"+
                  "G0_NATIVE_PAGE_16K_GUEST_4K_UNSUPPORTED_SAFE_DENIAL=1\n"+
                  "NO_HOST_EXTRA_GUEST_RW_SUBPAGE_EXPOSED=1\nEXIT_CODE=24\n"+log;
            boolean ok=rc==0 && exactMarkerCount(log,START)==1 &&
                 exactMarkerCount(log,MMAP)==1 &&
                 exactMarkerCount(log,STORE)==1 &&
                 exactMarkerCount(log,SUCCESS)==1 &&
                 log.indexOf(START)<log.indexOf(MMAP) &&
                 log.indexOf(MMAP)<log.indexOf(STORE) &&
                 log.indexOf(STORE)<log.indexOf(SUCCESS) &&
                 !log.contains("REJECTED") && !log.contains("FAIL_CLOSED");
            if(!ok)return "G0_ANDROID_GUEST_MMAP_PASS=0\nEXIT_CODE="+rc+"\n"+log;
            return "G0_ANDROID_FEX_REAL_GUEST_MMAP_MUNMAP_PASS=1\n"+
              "ORIGINAL_FEX_X86_GUEST_MMAP_EXECUTED=1\n"+
              "GUEST_BYTE_5A_STORED_AND_LOADED=1\n"+
              "ORIGINAL_FEX_X86_GUEST_MUNMAP_EXECUTED=1\n"+
              "NATIVE_PAGE_RELEASED=1\n"+
              "GUEST_DYNAMIC_LDSO_EXECUTED=0\n"+
              "GUEST_GLIBC_INITIALIZED=0\n"+
              "WINE_PROTON_GAME_EXECUTED=0\nEXIT_CODE=0\n"+log;
        } finally {if(child.isAlive())child.destroyForcibly();}
    }
    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);
        LinearLayout layout=new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(26,34,26,34);
        layout.setBackgroundColor(Color.rgb(11,20,31));
        TextView title=new TextView(this);
        title.setText("KERNIX / G0 REAL FEX MMAP");
        title.setTextColor(Color.WHITE);title.setTextSize(23);
        layout.addView(title);
        TextView explanation=new TextView(this);
        explanation.setText("اختبار منفصل: تنفيذ mmap ثم كتابة وقراءة البايت 5A ثم munmap بتعليمات x86 حقيقية داخل FEX على أندرويد.\n"+
          "لا يشغّل ld-linux أو glibc أو الألعاب ولا يغيّر النسخة المستقرة. لا يستخدم ملفات الجهاز ولا يحتاج صلاحيات.");
        explanation.setTextSize(16);explanation.setTextColor(0xffc2d6f1);
        layout.addView(explanation);
        go=new Button(this);go.setText("ابدأ اختبار الذاكرة الحقيقي");
        go.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX G0")
            .setMessage("اختبار محدود ومستقل داخل عملية تابعة مع مهلة انتهاء، يخصص صفحة ذاكرة مؤقتة فقط. تشغيل؟")
            .setPositiveButton("تشغيل",(d,n)->begin())
            .setNegativeButton("إلغاء",null).show());
        layout.addView(go);
        result=new TextView(this);result.setTextSize(13);
        result.setTextColor(Color.WHITE);
        result.setTextIsSelectable(true);
        result.setText("G0_ANDROID_FEX_REAL_GUEST_MMAP_MUNMAP_NOT_STARTED=1");
        layout.addView(result);
        ScrollView sc=new ScrollView(this);sc.addView(layout);
        setContentView(sc);
    }
    private void begin(){
        if(!running.compareAndSet(false,true))return;
        go.setEnabled(false);
        result.setText("G0_ANDROID_FEX_MMAP_RUNNING=1");
        new Thread(()->{
            String output;
            try{output=execute();}
            catch(Exception e){
                output="G0_ANDROID_GUEST_MMAP_PASS=0\nG0_SAFE_FAILURE=1\n"+
                  e.getClass().getSimpleName()+": "+e.getMessage();
            }finally{running.set(false);}
            final String show=output;
            runOnUiThread(()->{
                if(isFinishing()||isDestroyed())return;
                result.setText(show);go.setEnabled(true);
            });
        },"g0-fex-owned-vm").start();
    }
}
