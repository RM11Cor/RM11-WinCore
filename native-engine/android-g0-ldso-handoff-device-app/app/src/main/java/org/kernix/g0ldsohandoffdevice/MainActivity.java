package org.kernix.g0ldsohandoffdevice;

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

/** Bounded same-original-FEX session: source-pinned ELF/AUXV and heap syscalls
 * then one authentic original ld-linux MOV at PT_INTERP RIP; no glibc. */
public final class MainActivity extends Activity {
  private static final int LOG_CAP=24576;
  private static final String EXEC="libkernix_g0_original_ldso_after_heap.so";
  private static final String CORE="libFEXCore.so";
  private static final String SUCCESS="KERNIX_G0_ELF_AUXV_FEX_HEAP_AND_ORIGINAL_LDSO_FIRST_MOV_ANDROID_NATIVE_PASS_BOUNDED_NO_FULL_LDSO";
  private static final String PREADED="KERNIX_G0_COMBINED_X86_HEAP_COPY_AND_MUNMAP_WITH_ORIGINAL_PIE_ALIVE";
  private static final String STARTED="KERNIX_G0_ORIGINAL_LDSO_ENTRY_AFTER_FEX_HEAP_START";
  private static final String LOADED="KERNIX_G0_COMBINED_FEX_ORIGINAL_ELF_AND_STACK_CONSUMED";
  private static final String MOV="KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_SOURCE_MOV_RSP_RDI_EXECUTED_AFTER_HEAP";
  private static final String RESTORED="KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_SOURCE_BYTES_RESTORED_WX_SAFE";
  private static final String[] FILENAMES={
    "bin/kernix-g2e-dynamic-guest",
    "lib64/ld-linux-x86-64.so.2",
    "lib/x86_64-linux-gnu/libc.so.6"
  };
  private static final long[] LENGTHS={15976,235408,2118168};
  private static final String[] HASHES={
    "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412",
    "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae",
    "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
  };
  private final AtomicBoolean busy=new AtomicBoolean(false);
  private TextView report;
  private Button start;

  private static String sha(byte[] bytes)throws Exception {
    MessageDigest md=MessageDigest.getInstance("SHA-256");
    md.update(bytes);
    return hex(md.digest());
  }
  private static String shaFile(Path file)throws Exception {
    MessageDigest md=MessageDigest.getInstance("SHA-256");
    try(InputStream in=Files.newInputStream(file)) {
      byte[] buffer=new byte[8192];int n;
      while((n=in.read(buffer))>=0)if(n>0)md.update(buffer,0,n);
    }
    return hex(md.digest());
  }
  private static String hex(byte[] data) {
    StringBuilder out=new StringBuilder(64);
    for(byte b:data) {
      out.append(Character.forDigit((b>>4)&15,16));
      out.append(Character.forDigit(b&15,16));
    }
    return out.toString();
  }
  private String assetText(String name)throws Exception {
    try(InputStream in=getAssets().open(name)){
      byte[] bytes=in.readAllBytes();
      if(bytes.length<64||bytes.length>128)
        throw new IOException("BAD_HASH_ASSET");
      return new String(bytes,StandardCharsets.US_ASCII).trim();
    }
  }
  private static void ownedDir(Path p)throws Exception {
    if(Files.exists(p,LinkOption.NOFOLLOW_LINKS)) {
      if(Files.isSymbolicLink(p) || !Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))
        throw new IOException("G0_PRIVATE_DIRECTORY_REJECTED");
    } else Files.createDirectory(p);
    Os.chmod(p.toString(),0700);
  }
  private static int markerCount(String all,String wanted) {
    int n=0;
    for(String line:all.split("\\R"))if(line.equals(wanted))n++;
    return n;
  }
  private Path ensureGuestRoot()throws Exception {
    Path files=getFilesDir().toPath().toRealPath();
    Path root=files.resolve("g0-ldso-handoff-source-original");
    ownedDir(root);
    for(int i=0;i<FILENAMES.length;i++) {
      String rel=FILENAMES[i];
      Path target=root.resolve(rel).normalize();
      if(!target.startsWith(root))
        throw new IOException("G0_UNTRUSTED_GUEST_PATH");
      Path parent=target.getParent();
      Path cursor=root;
      for(Path item:root.relativize(parent)) {
        cursor=cursor.resolve(item);
        ownedDir(cursor);
      }
      if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)) {
        if(Files.isSymbolicLink(target) ||
           !Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS) ||
           Files.size(target)!=LENGTHS[i] ||
           !shaFile(target).equals(HASHES[i]))
          throw new IOException("G0_PREVIOUS_GUEST_FILE_FAILED_HASH_CHECK");
      } else {
        byte[] guest;
        try(InputStream in=getAssets().open("original/"+rel)){
          guest=in.readAllBytes();
        }
        if(guest.length!=LENGTHS[i] || !sha(guest).equals(HASHES[i]))
          throw new IOException("G0_SIGNED_ASSET_SHA256_REJECTED");
        Path tmp=Files.createTempFile(parent,".g0-", ".pending");
        try {
          Files.write(tmp,guest,StandardOpenOption.TRUNCATE_EXISTING);
          if(Files.size(tmp)!=LENGTHS[i] || !shaFile(tmp).equals(HASHES[i]))
            throw new IOException("G0_GUEST_WRITE_HASH_REJECTED");
          Os.chmod(tmp.toString(),0400);
          Files.move(tmp,target,StandardCopyOption.ATOMIC_MOVE);
        } finally {
          Files.deleteIfExists(tmp);
        }
      }
      Os.chmod(target.toString(),0400);
    }
    return root.toRealPath();
  }
  private Path nativeVerified(Path root,String filename,String digestAsset)throws Exception {
    Path f=root.resolve(filename);
    if(Files.isSymbolicLink(f) ||
       !Files.isRegularFile(f,LinkOption.NOFOLLOW_LINKS) ||
       !f.toRealPath().getParent().equals(root))
      throw new IOException("G0_SIGNED_NATIVE_FILE_REJECTED_"+filename);
    String expected=assetText(digestAsset);
    if(!expected.matches("[0-9a-f]{64}")||!shaFile(f).equals(expected))
      throw new IOException("G0_NATIVE_SHA256_REJECTED_"+filename);
    return f;
  }
  private String run()throws Exception {
    Path libs=new File(getApplicationInfo().nativeLibraryDir).toPath().toRealPath();
    Path exe=nativeVerified(libs,EXEC,"original-ldso-after-heap-runner.sha256");
    nativeVerified(libs,CORE,"original-fexcore.sha256");
    if(!Files.isExecutable(exe))return "G0_LDSO_HANDOFF_NATIVE_CHILD_NOT_EXECUTABLE=1";
    Path root=ensureGuestRoot();
    ProcessBuilder pb=new ProcessBuilder(exe.toString(),root.toString());
    pb.directory(getFilesDir());
    pb.environment().clear();
    pb.environment().put("LD_LIBRARY_PATH",libs.toString());
    pb.redirectErrorStream(true);
    final Process child=pb.start();
    final ByteArrayOutputStream logBytes=new ByteArrayOutputStream();
    final AtomicBoolean badLog=new AtomicBoolean(false);
    Thread drain=new Thread(()->{
      try(InputStream in=child.getInputStream()){
        byte[] buf=new byte[512];int n;
        while((n=in.read(buf))!=-1) {
          if(logBytes.size()+n>LOG_CAP) {
            badLog.set(true);child.destroyForcibly();break;
          }
          logBytes.write(buf,0,n);
        }
      } catch(Exception e){badLog.set(true);child.destroyForcibly();}
    },"g0-original-ldso-after-heap-log");
    drain.start();
    try {
      boolean finished=child.waitFor(40,TimeUnit.SECONDS);
      if(!finished)child.destroyForcibly();
      drain.join(1800);
      if(drain.isAlive()){
        child.destroyForcibly();drain.interrupt();drain.join(400);
      }
      if(!finished)return "G0_LDSO_HANDOFF_CHILD_WATCHDOG_TIMEOUT=1";
      if(badLog.get()||drain.isAlive())
        return "G0_LDSO_HANDOFF_CHILD_LOG_FAILED=1";
      String output=new String(logBytes.toByteArray(),StandardCharsets.UTF_8);
      int rc=child.exitValue();
      boolean ok=rc==0 &&
        markerCount(output,SUCCESS)==1 &&
        markerCount(output,PREADED)==1 &&
        markerCount(output,LOADED)==1 &&
        markerCount(output,STARTED)==1 &&
        markerCount(output,MOV)==1 &&
        markerCount(output,RESTORED)==1 &&
        output.indexOf(STARTED)<output.indexOf(LOADED) &&
        output.indexOf(LOADED)<output.indexOf(PREADED) &&
        output.indexOf(PREADED)<output.indexOf(MOV) &&
        output.indexOf(MOV)<output.indexOf(RESTORED) &&
        output.indexOf(RESTORED)<output.indexOf(SUCCESS) &&
        !output.contains("REJECTED") && !output.contains("FAIL_CLOSED");
      if(!ok)return "G0_ANDROID_SOURCE_LDSO_FIRST_MOV_AFTER_HEAP_PASS=0\nEXIT_CODE="+rc+"\n"+output;
      return "G0_ANDROID_SOURCE_LDSO_FIRST_MOV_AFTER_HEAP_PASS=1\n"+
        "ORIGINAL_FEX_X86_GUEST_ELF_AND_AUXV_READ=1\n"+
        "ORIGINAL_FEX_X86_MMAP_STORE_LOAD_MUNMAP_EXECUTED=1\n"+
        "ORIGINAL_LDSO_FIRST_SOURCE_INSTRUCTION_EXECUTED=1\n"+
        "ORIGINAL_LDSO_SOURCE_BYTES_RESTORED_WX_SAFE=1\n"+
        "FULL_DYNAMIC_LOADER_STARTUP=0\n"+
        "GUEST_GLIBC_INITIALIZED=0\n"+
        "WINE_PROTON_GAMES_EXECUTED=0\nEXIT_CODE=0\n"+output;
    } finally {if(child.isAlive())child.destroyForcibly();}
  }
  @Override public void onCreate(Bundle b){
    super.onCreate(b);
    LinearLayout col=new LinearLayout(this);col.setOrientation(1);
    col.setPadding(30,34,30,34);col.setBackgroundColor(Color.rgb(12,20,31));
    TextView title=new TextView(this);title.setText("KERNIX / G0 ORIGINAL LDSO HANDOFF");
    title.setTextSize(22);title.setTextColor(Color.WHITE);col.addView(title);
    TextView desc=new TextView(this);
    desc.setText("اختبار جديد على أندرويد: بعد تشغيل mmap وmunmap داخل نفس FEX، ننفّذ أول تعليمة أصلية من ld-linux ثم نوقفه بحدّ آمن ونعيد بايتات ELF الأصلية.\n"+
      "لا يشغّل المحمّل الديناميكي أو glibc أو الألعاب، ولا يحتاج روت، ولا يغيّر KERNIX المستقر.");
    desc.setTextSize(16);desc.setTextColor(0xffc8d8ee);col.addView(desc);
    start=new Button(this);start.setText("ابدأ اختبار دخول ld-linux بعد الذاكرة");
    start.setOnClickListener(v->new AlertDialog.Builder(this)
      .setTitle("KERNIX G0")
      .setMessage("يعمل الاختبار على ملفات أصلية ثابتة ضمن التخزين الخاص للتطبيق، وبعملية FEX مستقلة ومحدودة. تشغيل؟")
      .setPositiveButton("ابدأ",(d,n)->launch())
      .setNegativeButton("إلغاء",null).show());
    col.addView(start);
    report=new TextView(this);report.setTextColor(Color.WHITE);
    report.setTextSize(13);report.setTextIsSelectable(true);
    report.setText("G0_LDSO_HANDOFF_DEVICE_NOT_STARTED=1");
    col.addView(report);
    ScrollView sc=new ScrollView(this);sc.addView(col);setContentView(sc);
  }
  private void launch(){
    if(!busy.compareAndSet(false,true))return;
    start.setEnabled(false);report.setText("G0_LDSO_HANDOFF_DEVICE_RUNNING=1");
    new Thread(()->{
      String result;
      try{result=run();}
      catch(Exception e){result="G0_LDSO_HANDOFF_SAFE_FAILURE=1\n"+
        e.getClass().getSimpleName()+": "+e.getMessage();}
      finally{busy.set(false);}
      final String show=result;
      runOnUiThread(()->{
        if(isFinishing()||isDestroyed())return;
        report.setText(show);start.setEnabled(true);
      });
    },"g0-original-ldso-after-heap").start();
  }
}
