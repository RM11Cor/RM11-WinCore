package org.kernix.g0elfdevice;
import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Android opt-in: signed immutable FEXCore and original fixed GNU x86 ELF child. */
public final class MainActivity extends Activity {
  private static final String GUEST="KERNIX_ELF64_GUEST_RUN_PASS";
  private static final String WRITE="KERNIX_G0_REAL_FEX_ELF64_GUEST_WRITE_VM_BRIDGE_PASS";
  private static final String PID="KERNIX_G0_REAL_FEX_ELF64_GUEST_GETPID_BRIDGE_PASS";
  private static final String END="KERNIX_G0_ANDROID_BIONIC_GUEST_ELF_REAL_WRITE_GETPID_BOUNDARY_COMPLETED";
  private static final String FIN="KERNIX_FEXCORE_ANDROID_REAL_ELF64_X86_GUEST_EXEC_PROOF_V1";
  private final AtomicBoolean busy=new AtomicBoolean(false);
  private TextView report;
  private Button start;

  private static String hash(Path file) throws Exception {
    MessageDigest d=MessageDigest.getInstance("SHA-256");
    try(InputStream in=Files.newInputStream(file)) {
      byte[] b=new byte[8192];int n;
      while((n=in.read(b))!=-1)if(n>0)d.update(b,0,n);
    }
    StringBuilder s=new StringBuilder();
    for(byte b:d.digest()) {
      s.append(Character.forDigit((b>>4)&15,16));
      s.append(Character.forDigit(b&15,16));
    }
    return s.toString();
  }
  private String asset(String n)throws Exception {
    try(InputStream in=getAssets().open(n)) {
      byte[] b=in.readAllBytes();
      if(b.length>128)throw new IOException("OVERSIZE_DIGEST");
      return new String(b,StandardCharsets.US_ASCII).trim();
    }
  }
  private Path checked(Path root,String name,String stamp)throws Exception {
    Path file=root.resolve(name);
    if(Files.isSymbolicLink(file) ||
       !Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) ||
       !file.toRealPath().getParent().equals(root))
       throw new IOException("NATIVE_PATH_REJECTED_"+name);
    String expected=asset(stamp);
    if(!expected.matches("[0-9a-f]{64}") || !hash(file).equals(expected))
       throw new IOException("NATIVE_SHA256_REJECTED_"+name);
    return file;
  }
  private static int lines(String log,String marker) {
    int n=0;
    for(String s:log.split("\\R"))if(s.equals(marker))n++;
    return n;
  }
  private String execute() throws Exception {
    Path root=new File(getApplicationInfo().nativeLibraryDir).toPath().toRealPath();
    Path runner=checked(root,"libkernix_g0_elf_exec.so","runner.sha256");
    checked(root,"libFEXCore.so","fexcore.sha256");
    if(!Files.isExecutable(runner))return "G0_CHILD_NOT_EXECUTABLE=1";
    ProcessBuilder pb=new ProcessBuilder(runner.toString());
    pb.directory(getFilesDir());
    pb.environment().clear();
    pb.environment().put("LD_LIBRARY_PATH",root.toString());
    pb.redirectErrorStream(true);
    final Process child=pb.start();
    final AtomicBoolean overflow=new AtomicBoolean(false);
    ByteArrayOutputStream output=new ByteArrayOutputStream();
    Thread reader=new Thread(()->{
      try(InputStream in=child.getInputStream()) {
        byte[] b=new byte[512];int n;
        while((n=in.read(b))!=-1) {
          if(output.size()+n>24576) {
            overflow.set(true);
            child.destroyForcibly();
            break;
          }
          output.write(b,0,n);
        }
      } catch(Exception e) {overflow.set(true);child.destroyForcibly();}
    },"g0-child-output");
    reader.start();
    try {
      boolean finished=child.waitFor(22,TimeUnit.SECONDS);
      if(!finished)child.destroyForcibly();
      reader.join(1500);
      if(reader.isAlive()) {
        child.destroyForcibly();reader.interrupt();reader.join(500);
      }
      if(!finished)return "G0_CHILD_WATCHDOG_TIMEOUT=1";
      if(reader.isAlive() || overflow.get())return "G0_CHILD_LOG_TOO_LONG_OR_UNREADABLE=1";
      String log=new String(output.toByteArray(),StandardCharsets.UTF_8);
      int rc=child.exitValue();
      boolean ok=rc==0 && lines(log,GUEST)==1 && lines(log,WRITE)==1 &&
         lines(log,PID)==1 && lines(log,END)==1 && lines(log,FIN)==1 &&
         log.indexOf(WRITE)<log.indexOf(PID) && !log.contains("REJECTED");
      if(!ok)return "G0_ANDROID_ELF_DEVICE_PASS=0\nEXIT_CODE="+rc+"\n"+log;
      return "G0_ANDROID_ELF_DEVICE_PASS=1\n"+
        "REAL_GNU_X86_ELF_FEX_EXEC=1\nREAL_GUEST_WRITE=1\n"+
        "REAL_GUEST_GETPID=1\nGUEST_LDSO_GLIBC_EXECUTED=0\n"+
        "WINE_PROTON_GAME_EXECUTED=0\nEXIT_CODE=0\n"+log;
    } finally {if(child.isAlive())child.destroyForcibly();}
  }
  @Override public void onCreate(Bundle b) {
    super.onCreate(b);
    LinearLayout root=new LinearLayout(this);root.setOrientation(1);
    root.setPadding(30,36,30,36);root.setBackgroundColor(Color.rgb(11,19,31));
    TextView heading=new TextView(this);heading.setText("KERNIX / G0 REAL ELF");
    heading.setTextSize(22);heading.setTextColor(Color.WHITE);root.addView(heading);
    TextView info=new TextView(this);
    info.setText("اختبار منفصل لتشغيل برنامج Linux x86-64 حقيقي ثابت باستخدام FEXCore داخل أندرويد.\n"+
      "يفحص write وgetpid فقط. لا يستخدم الجذر أو الألعاب ولا يغيّر KERNIX المستقر. "+
      "لا يشغّل glibc أو Wine/Proton. يمكن أن يفشل إذا منع أندرويد تشغيل الملف.");
    info.setTextSize(16);info.setTextColor(0xffccdfef);root.addView(info);
    start=new Button(this);start.setText("ابدأ اختبار G0 الحقيقي");
    start.setOnClickListener(v->new AlertDialog.Builder(this)
      .setTitle("KERNIX G0")
      .setMessage("تشغيل ملف x86 اختباري ثابت بعملية مستقلة لمدة لا تزيد على 22 ثانية. توافق؟")
      .setPositiveButton("ابدأ",(d,n)->launch()).setNegativeButton("إلغاء",null).show());
    root.addView(start);
    report=new TextView(this);report.setTextColor(Color.WHITE);
    report.setTextSize(14);report.setTextIsSelectable(true);
    report.setText("G0_DEVICE_NOT_STARTED=1");root.addView(report);
    ScrollView scroll=new ScrollView(this);scroll.addView(root);setContentView(scroll);
  }
  private void launch() {
    if(!busy.compareAndSet(false,true))return;
    start.setEnabled(false);report.setText("G0_RUNNING=1");
    new Thread(()->{
      String result;
      try{result=execute();}
      catch(Exception e){result="G0_SAFE_FAILURE=1\n"+e.getClass().getSimpleName()+": "+e.getMessage();}
      finally{busy.set(false);}
      String text=result;
      runOnUiThread(()->{
        if(isFinishing()||isDestroyed())return;
        report.setText(text);start.setEnabled(true);
      });
    },"g0-supervisor").start();
  }
}
