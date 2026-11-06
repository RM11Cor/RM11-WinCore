package org.kernix.diagnostics;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.system.Os;
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
import org.json.JSONArray;
import org.json.JSONObject;

/** One stable signed package for future source-attested KERNIX probes.
 * No root, Internet, arbitrary EXE picker, background work, or game access. */
public final class MainActivity extends Activity {
  private static final String[] GUEST={
    "bin/kernix-g2e-dynamic-guest",
    "lib64/ld-linux-x86-64.so.2",
    "lib/x86_64-linux-gnu/libc.so.6"
  };
  private static final int[] GUEST_LENGTH={15976,235408,2118168};
  private static final String[] GUEST_SHA={
    "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412",
    "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
    "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
  };
  private static final int LOG_LIMIT=24576;
  private final AtomicBoolean busy=new AtomicBoolean(false);
  private JSONObject current;
  private TextView report;
  private Button runButton;

  private static String digest(InputStream stream)throws Exception {
    MessageDigest md=MessageDigest.getInstance("SHA-256");
    byte[] chunk=new byte[8192];int n;
    while((n=stream.read(chunk))!=-1) if(n>0)md.update(chunk,0,n);
    StringBuilder hex=new StringBuilder();
    for(byte x:md.digest()){
      hex.append(Character.forDigit((x>>4)&15,16));
      hex.append(Character.forDigit(x&15,16));
    }
    return hex.toString();
  }
  private static String sha(Path p)throws Exception {
    try(InputStream in=Files.newInputStream(p)){return digest(in);}
  }
  private static byte[] readAtMost(InputStream in,int max)throws IOException {
    ByteArrayOutputStream out=new ByteArrayOutputStream();
    byte[] buffer=new byte[1024];int n;
    while((n=in.read(buffer))!=-1){
      if(out.size()+n>max)throw new IOException("KERNIX_ASSET_SIZE_CAP");
      out.write(buffer,0,n);
    }
    return out.toByteArray();
  }
  private byte[] asset(String key,int max)throws Exception {
    try(InputStream in=getAssets().open(key)){return readAtMost(in,max);}
  }
  private JSONObject manifest()throws Exception {
    JSONObject j=new JSONObject(new String(asset("current-probe.json",8192),
      StandardCharsets.UTF_8));
    if(!"kernix.diagnostics.probe.v1".equals(j.getString("schema")))
      throw new IOException("KERNIX_UNKNOWN_PROBE_SCHEMA");
    if(j.optBoolean("enabled",false)){
      if(!j.getString("nativeRunner").matches("libkernix_[a-z0-9_]+\\.so") ||
         !j.getString("runnerDigestAsset").matches("[a-z0-9_-]+\\.sha256") ||
         j.getJSONArray("orderedNativeMarkers").length()<2 ||
         j.getJSONArray("orderedNativeMarkers").length()>12 ||
         j.getString("acceptedPhonePassKey").length()>100 ||
         j.getInt("watchdogSeconds")<5 || j.getInt("watchdogSeconds")>45)
        throw new IOException("KERNIX_PROBE_MANIFEST_REJECTED");
    }
    return j;
  }
  private void privateDir(Path p)throws Exception {
    if(Files.exists(p,LinkOption.NOFOLLOW_LINKS)){
      if(Files.isSymbolicLink(p) || !Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))
        throw new IOException("KERNIX_NOT_PRIVATE_DIR");
    }else Files.createDirectory(p);
    Os.chmod(p.toString(),0700);
  }
  private Path guestRoot()throws Exception {
    Path files=getFilesDir().toPath().toRealPath();
    Path root=files.resolve("source-pinned-guest");
    privateDir(root);
    for(int i=0;i<GUEST.length;i++){
      String rel=GUEST[i];
      Path dest=root.resolve(rel).normalize();
      if(!dest.startsWith(root))throw new IOException("KERNIX_GUEST_ESCAPE");
      Path cursor=root;
      for(Path part:root.relativize(dest.getParent())){
        cursor=cursor.resolve(part);
        privateDir(cursor);
      }
      if(!Files.exists(dest,LinkOption.NOFOLLOW_LINKS)){
        byte[] source=asset("original/"+rel,GUEST_LENGTH[i]+1);
        if(source.length!=GUEST_LENGTH[i])
          throw new IOException("KERNIX_GUEST_SOURCE_LENGTH_REJECTED");
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        md.update(source);
        StringBuilder h=new StringBuilder();
        for(byte b:md.digest()){h.append(Character.forDigit((b>>4)&15,16));h.append(Character.forDigit(b&15,16));}
        if(!h.toString().equals(GUEST_SHA[i]))
          throw new IOException("KERNIX_GUEST_SOURCE_SHA_REJECTED");
        Path tmp=Files.createTempFile(dest.getParent(),".signed-", ".pending");
        try{
          Files.write(tmp,source,StandardOpenOption.TRUNCATE_EXISTING);
          if(!sha(tmp).equals(GUEST_SHA[i]))
            throw new IOException("KERNIX_GUEST_STAGED_SHA_REJECTED");
          Os.chmod(tmp.toString(),0400);
          Files.move(tmp,dest,StandardCopyOption.ATOMIC_MOVE);
        } finally {Files.deleteIfExists(tmp);}
      }
      if(Files.isSymbolicLink(dest) || !Files.isRegularFile(dest,LinkOption.NOFOLLOW_LINKS) ||
         Files.size(dest)!=GUEST_LENGTH[i] || !sha(dest).equals(GUEST_SHA[i]))
        throw new IOException("KERNIX_GUEST_PREVIOUS_SHA_REJECTED");
      Os.chmod(dest.toString(),0400);
    }
    return root.toRealPath();
  }
  private Path verifiedLib(Path libs,String file,String assetName)throws Exception {
    Path p=libs.resolve(file).normalize();
    if(!p.getParent().equals(libs) || Files.isSymbolicLink(p) ||
       !Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS) ||
       !p.toRealPath().getParent().equals(libs))
      throw new IOException("KERNIX_NATIVE_NOT_OWNED");
    String expected=new String(asset(assetName,128),StandardCharsets.US_ASCII).trim();
    if(!expected.matches("[0-9a-f]{64}")||!sha(p).equals(expected))
      throw new IOException("KERNIX_NATIVE_SHA256_MISMATCH");
    return p;
  }
  private static int countExact(String output,String marker) {
    int hits=0;
    for(String line:output.split("\\R"))if(line.equals(marker))hits++;
    return hits;
  }
  private String execute()throws Exception {
    JSONObject spec=current;
    if(spec==null || !spec.optBoolean("enabled",false))
      return "KERNIX_DIAGNOSTIC_RUNTIME_NOT_RELEASED=1";
    Path libs=new File(getApplicationInfo().nativeLibraryDir).toPath().toRealPath();
    Path exe=verifiedLib(libs,spec.getString("nativeRunner"),
                         spec.getString("runnerDigestAsset"));
    verifiedLib(libs,"libFEXCore.so","original-fexcore.sha256");
    if(!Files.isExecutable(exe))return "KERNIX_NATIVE_EXEC_DISABLED=1";
    Path root=guestRoot();
    ProcessBuilder pb=new ProcessBuilder(exe.toString(),root.toString());
    pb.directory(getFilesDir());
    pb.environment().clear();
    pb.environment().put("LD_LIBRARY_PATH",libs.toString());
    pb.redirectErrorStream(true);
    Process child=pb.start();
    ByteArrayOutputStream log=new ByteArrayOutputStream();
    AtomicBoolean badLog=new AtomicBoolean(false);
    Thread reader=new Thread(()->{
      try(InputStream in=child.getInputStream()){
        byte[] b=new byte[512];int n;
        while((n=in.read(b))!=-1){
          if(log.size()+n>LOG_LIMIT){badLog.set(true);child.destroyForcibly();break;}
          log.write(b,0,n);
        }
      }catch(Exception e){badLog.set(true);child.destroyForcibly();}
    },"kernix-diagnostics-reader");
    reader.start();
    try{
      boolean completed=child.waitFor(spec.getInt("watchdogSeconds"),TimeUnit.SECONDS);
      if(!completed)child.destroyForcibly();
      reader.join(1500);
      if(reader.isAlive()){child.destroyForcibly();reader.interrupt();reader.join(500);}
      if(!completed)return "KERNIX_DIAGNOSTIC_WATCHDOG_TIMEOUT=1";
      if(reader.isAlive()||badLog.get())return "KERNIX_DIAGNOSTIC_OUTPUT_LIMIT=1";
      int rc=child.exitValue();
      String output=new String(log.toByteArray(),StandardCharsets.UTF_8);
      JSONArray markers=spec.getJSONArray("orderedNativeMarkers");
      int last=-1;boolean passed=rc==0;
      for(int i=0;i<markers.length();i++){
        String m=markers.getString(i);
        if(m.isEmpty()||m.length()>200||countExact(output,m)!=1 ||
           output.indexOf(m)<=last){passed=false;break;}
        last=output.indexOf(m);
      }
      if(output.contains("REJECTED")||output.contains("FAIL_CLOSED"))
        passed=false;
      return spec.getString("acceptedPhonePassKey")+"="+(passed?"1":"0")+
          "\nEXIT_CODE="+rc+"\nFULL_LDSO_GLIBC_OR_WINE_GAME_PROVEN=0\n"+output;
    }finally{if(child.isAlive())child.destroyForcibly();}
  }
  private TextView text(LinearLayout col,String content,int size,int color){
    TextView t=new TextView(this);t.setText(content);t.setTextSize(size);
    t.setTextColor(color);t.setPadding(0,8,0,8);col.addView(t);return t;
  }
  @Override public void onCreate(Bundle b){
    super.onCreate(b);
    LinearLayout col=new LinearLayout(this);col.setPadding(28,32,28,32);
    col.setOrientation(1);col.setBackgroundColor(Color.rgb(10,18,30));
    text(col,"KERNIX Diagnostics",23,Color.WHITE);
    text(col,"تطبيق واحد قابل للتحديث لاختبارات المحرك المستقبلية. النسخة المستقرة وألعابك بدون تغيير.",
      15,0xffbfd4ed);
    try{
      current=manifest();
      text(col,"المرحلة الحالية: "+current.getString("title"),18,Color.WHITE);
      text(col,current.getString("scope"),14,0xffd0ddeb);
      text(col,"مراحل الهاتف المؤرشفة: FEX pread64، mmap/munmap، ELF+AUXV، وأول تعليمة أصلية من ld-linux.",14,0xff9ac6a9);
      if(current.optBoolean("enabled",false)){
        runButton=new Button(this);runButton.setText("تشغيل الاختبار الحالي");
        runButton.setOnClickListener(v->new AlertDialog.Builder(this)
          .setTitle("KERNIX Diagnostics")
          .setMessage("تشغيل اختبار FEX محدود في عملية فرعية تحت مراقبة مهلة التنفيذ، بعد فحص بصمات الملفات. متابعة؟")
          .setPositiveButton("تشغيل",(d,n)->start()).setNegativeButton("إلغاء",null).show());
        col.addView(runButton);
      }else text(col,"الاختبار التالي غير متاح إلى أن ينجح التنفيذ الفعلي على Linux وبناء Android والتحقق من التوقيع. لا حاجة لتنزيل أي APK الآن.",16,0xffffd28f);
    }catch(Exception e){
      text(col,"KERNIX_MANIFEST_REJECTED: "+e.getClass().getSimpleName(),15,0xffff9d9d);
    }
    report=text(col,"KERNIX_DEVICE_TEST_NOT_STARTED=1",12,Color.WHITE);
    report.setTextIsSelectable(true);
    ScrollView scroll=new ScrollView(this);scroll.addView(col);
    setContentView(scroll);
  }
  private void start(){
    if(current==null||!current.optBoolean("enabled",false) ||
       !busy.compareAndSet(false,true))return;
    runButton.setEnabled(false);
    report.setText("KERNIX_RUNNING_ONE_SIGNED_PROBE=1");
    new Thread(()->{
      String output;
      try{output=execute();}
      catch(Exception e){output="KERNIX_SAFE_FAILURE=1\n"+e.getClass().getSimpleName()+": "+e.getMessage();}
      finally{busy.set(false);}
      final String shown=output;
      runOnUiThread(()->{
        if(isFinishing()||isDestroyed())return;
        report.setText(shown);runButton.setEnabled(true);
      });
    },"kernix-diagnostics-one-probe").start();
  }
}
