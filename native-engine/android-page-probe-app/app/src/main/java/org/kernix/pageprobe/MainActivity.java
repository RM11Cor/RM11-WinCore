package org.kernix.pageprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An *independent*, opt-in, side-by-side native page capability diagnostic.
 * It does not load x86 Linux/ld-linux, FEX, Wine or any guest input.
 * A separate Bionic PIE child can only allocate one PROT_NONE native page.
 */
public final class MainActivity extends Activity {
    private static final String CHILD="libkernix_g2ec3d3_native_page_child.so";
    private static final String ARG=
        "--kernix-g2e-c3d3-kernel-native-page-noreplace-v1";
    private static final String POSITIVE=
        "KERNIX_G2EC3D3_DEVICE_NATIVE_PAGE_NOREPLACE_COLLISION_NO_GUEST_PASS";
    private final AtomicBoolean running=new AtomicBoolean(false);
    private TextView status;
    private Button button;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        final ScrollView scroll=new ScrollView(this);
        final LinearLayout layout=new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(36,48,36,44);
        layout.setBackgroundColor(Color.rgb(12,19,30));
        scroll.addView(layout);
        TextView title=new TextView(this);
        title.setText("KERNIX / C3-D3");
        title.setTextColor(Color.WHITE);
        title.setTextSize(24);
        title.setGravity(Gravity.CENTER);
        layout.addView(title);
        TextView message=new TextView(this);
        message.setText(
            "فحص حجم صفحة نواة أندرويد ودعم الحجز الآمن.\n" +
            "اختبار صفحة واحدة فقط داخل عملية منفصلة، بدون FEX أو ألعاب، " +
            "وبدون تعديل ملفات النظام أو نسخة KERNIX v0.27.\n" +
            "هذا الفحص لا يثبت تشغيل مكتبات Linux.");
        message.setTextColor(Color.rgb(213,222,236));
        message.setTextSize(16);
        message.setPadding(0,24,0,24);
        layout.addView(message);
        button=new Button(this);
        button.setText("بدء فحص أندرويد الآمن");
        button.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX C3-D3")
            .setMessage(
                "سيجري فحص صفحة واحدة بصلاحية PROT_NONE لمدة قصيرة، " +
                "ويتحقق من منع استبدالها. لا تُشغَّل أي تعليمات x86. هل توافق؟")
            .setNegativeButton("إلغاء",(dialog,which)->{})
            .setPositiveButton("بدء الفحص",(dialog,which)->startProbe())
            .show());
        layout.addView(button);
        status=new TextView(this);
        status.setTextColor(Color.rgb(232,239,249));
        status.setTextSize(15);
        status.setTextIsSelectable(true);
        status.setText("لم يبدأ الفحص. برنامج C3-D3 مستقل عن المحاكي.");
        status.setPadding(0,28,0,24);
        layout.addView(status);
        setContentView(scroll);
    }

    private static String expectedDigest(
            android.content.res.AssetManager manager) throws IOException {
        try(InputStream input=manager.open("c3d3-native-runner.sha256")) {
            ByteArrayOutputStream data=new ByteArrayOutputStream();
            byte[] chunk=new byte[128];
            int size;
            while((size=input.read(chunk))!=-1) {
                if(data.size()+size>128)
                    throw new IOException("RUNNER_SHA256_TOO_LONG");
                data.write(chunk,0,size);
            }
            String sha=new String(data.toByteArray(),
                                  StandardCharsets.US_ASCII).trim();
            if(!sha.matches("[0-9a-f]{64}"))
                throw new IOException("RUNNER_SHA256_ASSET_REJECTED");
            return sha;
        }
    }
    private static String digest(Path file) throws IOException {
        try {
            MessageDigest hash=MessageDigest.getInstance("SHA-256");
            try(InputStream in=Files.newInputStream(file)){
                byte[] block=new byte[8192];
                int n;
                while((n=in.read(block))!=-1)
                    hash.update(block,0,n);
            }
            StringBuilder result=new StringBuilder(64);
            for(byte value:hash.digest()) {
                result.append(Character.forDigit((value&255)>>>4,16));
                result.append(Character.forDigit(value&15,16));
            }
            return result.toString();
        } catch(NoSuchAlgorithmException problem) {
            throw new IOException("SHA256_MISSING",problem);
        }
    }
    private String verifyAndProbe() throws Exception {
        final File libraryRoot=new File(getApplicationInfo().nativeLibraryDir);
        final Path root=libraryRoot.toPath().toRealPath();
        if(Files.isSymbolicLink(root) ||
           !Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("APK_NATIVE_ROOT_INVALID");
        final Path runner=root.resolve(CHILD);
        if(Files.isSymbolicLink(runner) ||
           !Files.isRegularFile(runner,LinkOption.NOFOLLOW_LINKS) ||
           !runner.toRealPath().getParent().equals(root))
            throw new IOException("SIGNED_RUNNER_PATH_REJECTED");
        if(!digest(runner).equals(expectedDigest(getAssets())))
            throw new IOException("SIGNED_RUNNER_DIGEST_REJECTED");
        if(!Files.isExecutable(runner))
            throw new IOException("RUNNER_NOT_EXECUTABLE");
        Process child=null;
        try {
            ProcessBuilder build=new ProcessBuilder(
                runner.toRealPath().toString(),ARG);
            build.directory(getFilesDir());
            build.redirectErrorStream(true);
            build.environment().clear();
            child=build.start();
            boolean finished=child.waitFor(6,TimeUnit.SECONDS);
            if(!finished) {
                child.destroyForcibly();
                return "KERNIX_G2EC3D3_CHILD_TIMEOUT_NO_PROOF";
            }
            ByteArrayOutputStream collected=new ByteArrayOutputStream();
            try(InputStream pipe=child.getInputStream()) {
                byte[] chunk=new byte[1024];
                int size;
                while((size=pipe.read(chunk))!=-1) {
                    if(collected.size()+size>2048)
                        return "KERNIX_G2EC3D3_CHILD_OUTPUT_TOO_LARGE";
                    collected.write(chunk,0,size);
                }
            }
            String result=new String(collected.toByteArray(),
                                     StandardCharsets.UTF_8).trim();
            int exit=child.exitValue();
            if(result.length()>2048)
                return "KERNIX_G2EC3D3_CHILD_OUTPUT_TOO_LARGE";
            if(exit!=0)
                return "KERNIX_G2EC3D3_CHILD_FAIL_CLOSED exit="+exit+
                       "\n"+result;
            final String[] lines=result.split("\\R");
            if(lines.length!=8 || !POSITIVE.equals(lines[0]) ||
               !lines[1].matches("NATIVE_KERNEL_PAGE_BYTES=(4096|16384)") ||
               !lines[2].matches("NATIVE_KERNEL_16K=[01]") ||
               !lines[3].equals("NOREPLACE_EXISTING_MAPPING_PRESERVED=1") ||
               !lines[4].equals("ISOLATED_NATIVE_PAGE_RELEASED=1") ||
               !lines[5].equals("FEX_EXECUTED=0") ||
               !lines[6].equals("LINUX_LDSO_EXECUTED=0") ||
               !lines[7].equals("GUEST_NATIVE_VA_RESERVED=0"))
                return "KERNIX_G2EC3D3_UNEXPECTED_CHILD_PROTOCOL_REJECTED";
            String nativeValue=lines[1].substring(
                "NATIVE_KERNEL_PAGE_BYTES=".length());
            boolean is16k=nativeValue.equals("16384");
            if(!lines[2].equals("NATIVE_KERNEL_16K="+(is16k?"1":"0")))
                return "KERNIX_G2EC3D3_INCONSISTENT_NATIVE_KERNEL_PAGE";
            return (is16k ? "نتيجة الجهاز: نواة أندرويد 16KB مؤكدة.\n" :
                            "نتيجة الجهاز: نواة أندرويد 4KB مؤكدة.\n") +
                   "اختبار رفض الحجز المتداخل: نجح.\n" +
                   "لم تُشغّل مكتبات Linux أو FEX.\n\n"+result;
        } finally {
            if(child!=null)child.destroyForcibly();
        }
    }
    private void startProbe() {
        if(!running.compareAndSet(false,true))return;
        button.setEnabled(false);
        status.setText("فحص الجهاز قيد التنفيذ داخل عملية منفصلة...");
        new Thread(()->{
            String result;
            try {
                result=verifyAndProbe();
            }catch(Exception problem) {
                result="KERNIX_G2EC3D3_SAFE_FAILURE: "+
                       problem.getClass().getSimpleName()+
                       ": "+problem.getMessage();
            }finally{
                running.set(false);
            }
            final String message=result;
            runOnUiThread(()->{
                status.setText(message);
                button.setEnabled(true);
            });
        },"kernix-page-probe").start();
    }
}
