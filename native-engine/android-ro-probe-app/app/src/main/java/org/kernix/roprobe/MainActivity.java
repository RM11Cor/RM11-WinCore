package org.kernix.roprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.system.Os;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

// Explicitly opt-in, independent, unprivileged Bionic-only memory probe.
// The original Linux x86 ELF, dynamic linker and glibc are DATA ONLY.
// This app contains NO FEX, Wine, DXVK or guest execution path.
public final class MainActivity extends Activity {
    private static final String CHILD="libkernix_g2ec3d6_ro_child.so";
    private static final String FLAG=
        "--kernix-g2e-c3d6r2-host-chosen-4k-ro-probe-v1";
    private static final String MARKER=
        "KERNIX_G2EC3D6R2_DEVICE_609_GUEST4K_HOST_CHOSEN_RO_NO_FEX_PASS";
    private static final String ROOT="c3d6-root";
    private final AtomicBoolean running=new AtomicBoolean(false);
    private TextView status;
    private Button button;

    private static final class Spec {
        final String name,sha;
        final long size;
        Spec(String n,long z,String h) { name=n;size=z;sha=h; }
    }
    private static final Spec[] FILES={
        new Spec("bin/kernix-g2e-dynamic-guest",15976,
            "9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"),
        new Spec("lib64/ld-linux-x86-64.so.2",235408,
            "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"),
        new Spec("lib/x86_64-linux-gnu/libc.so.6",2118168,
            "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906")
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll=new ScrollView(this);
        LinearLayout layout=new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(36,48,36,44);
        layout.setBackgroundColor(Color.rgb(12,19,30));
        scroll.addView(layout);
        TextView title=new TextView(this);
        title.setText("KERNIX / C3-D6 R2");
        title.setGravity(Gravity.CENTER);
        title.setTextSize(24);
        title.setTextColor(Color.WHITE);
        layout.addView(title);
        TextView explanation=new TextView(this);
        explanation.setText("فحص مصحح لذاكرة Linux على أندرويد 4KB.\n"+
            "يستخدم نافذة ذاكرة يحدد موقعها أندرويد لحماية 609 صفحات دون فرض العناوين العالية المرفوضة.\n"+
            "لا ينفذ FEX أو Linux أو Wine. عناوين Linux تبقى بيانات ترجمة فقط، وليس تشغيل برامج. لا يغير v0.27. "+
            "ممكن يفشل إذا النظام لا يسمح بعناوين الذاكرة المطلوبة.");
        explanation.setTextColor(Color.rgb(218,231,245));
        explanation.setTextSize(16);
        explanation.setPadding(0,24,0,24);
        layout.addView(explanation);
        button=new Button(this);
        button.setText("فحص الذاكرة المصحح C3-D6 R2");
        button.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX C3-D6")
            .setMessage("هل توافق على اختبار حجز 609 صفحات، ضمن عملية مستقلة "+
                "ووقت محدود، دون صلاحيات أو تشغيل تعليمات x86؟")
            .setNegativeButton("إلغاء",(d,w)->{})
            .setPositiveButton("بدء الفحص",(d,w)->startTest())
            .show());
        layout.addView(button);
        status=new TextView(this);
        status.setText("لم يبدأ الفحص.");
        status.setTextColor(Color.rgb(235,241,252));
        status.setTextIsSelectable(true);
        status.setTextSize(15);
        status.setPadding(0,28,0,20);
        layout.addView(status);
        setContentView(scroll);
    }
    private static String sha256(Path path) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(path)) {
            byte[] block=new byte[8192];
            int n;
            while((n=in.read(block))!=-1)digest.update(block,0,n);
        }
        StringBuilder s=new StringBuilder();
        for(byte b:digest.digest()) {
            s.append(Character.forDigit((b&255)>>>4,16));
            s.append(Character.forDigit(b&15,16));
        }
        return s.toString();
    }
    private static Path ensurePrivateDirectory(Path path) throws Exception {
        if(Files.isSymbolicLink(path))throw new IOException("SYMLINK_DIR_REJECTED");
        Files.createDirectories(path);
        if(Files.isSymbolicLink(path) ||
           !Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("INVALID_DIRECTORY");
        Os.chmod(path.toString(),0700);
        return path.toRealPath();
    }
    private static boolean fileMatches(Path file,Spec spec) throws Exception {
        return !Files.isSymbolicLink(file) &&
               Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) &&
               Files.size(file)==spec.size && sha256(file).equals(spec.sha);
    }
    private Path prepareGuest() throws Exception {
        Path base=getFilesDir().toPath().toRealPath();
        Path root=ensurePrivateDirectory(base.resolve(ROOT));
        if(!root.getParent().equals(base))
            throw new IOException("GUEST_ROOT_OUTSIDE_APP");
        for(Spec spec:FILES) {
            Path dest=root.resolve(spec.name).normalize();
            if(!dest.startsWith(root))throw new IOException("GUEST_ESCAPE");
            Path dir=root;
            String[] segments=spec.name.split("/");
            for(int i=0;i<segments.length-1;++i)
                dir=ensurePrivateDirectory(dir.resolve(segments[i]));
            if(!dir.equals(dest.getParent()))
                throw new IOException("GUEST_PARENT_CHANGED");
            if(fileMatches(dest,spec))continue;
            Path temp=Files.createTempFile(dir,"c3d6-", ".stage");
            try {
                long count=0;
                try(InputStream in=getAssets().open("original/"+spec.name);
                    OutputStream out=Files.newOutputStream(temp)) {
                    byte[] buf=new byte[8192];
                    int n;
                    while((n=in.read(buf))!=-1) {
                        count+=n;
                        if(count>spec.size)throw new IOException("ASSET_TOO_LARGE");
                        out.write(buf,0,n);
                    }
                }
                if(count!=spec.size || !sha256(temp).equals(spec.sha))
                    throw new IOException("ORIGINAL_ELF_HASH_REJECTED:"+spec.name);
                Os.chmod(temp.toString(),0400);
                Files.move(temp,dest,StandardCopyOption.ATOMIC_MOVE,
                           StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(temp);
            }
            if(!fileMatches(dest,spec))
                throw new IOException("STAGED_GUEST_DIGEST_REJECTED");
        }
        return root;
    }
    private String execute() throws Exception {
        File dir=new File(getApplicationInfo().nativeLibraryDir);
        Path libRoot=dir.toPath().toRealPath();
        Path runner=libRoot.resolve(CHILD);
        if(Files.isSymbolicLink(runner) ||
           !Files.isRegularFile(runner,LinkOption.NOFOLLOW_LINKS) ||
           !runner.toRealPath().getParent().equals(libRoot) ||
           !Files.isExecutable(runner))
            throw new IOException("SIGNED_NATIVE_CHILD_INVALID");
        String expected;
        try(InputStream in=getAssets().open("runner.sha256")) {
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();
            byte[] chunk=new byte[80]; int n;
            while((n=in.read(chunk))!=-1) {
                if(bytes.size()+n>128)throw new IOException("RUNNER_DIGEST_TOO_LONG");
                bytes.write(chunk,0,n);
            }
            expected=new String(bytes.toByteArray(),StandardCharsets.US_ASCII).trim();
        }
        if(!expected.matches("[0-9a-f]{64}") ||
           !sha256(runner).equals(expected))
            throw new IOException("SIGNED_CHILD_SHA256_REJECTED");
        Path guest=prepareGuest();
        Process child=null;
        try {
            ProcessBuilder builder=new ProcessBuilder(
                runner.toRealPath().toString(), FLAG, guest.toString());
            builder.directory(getFilesDir());
            builder.environment().clear();
            builder.redirectErrorStream(true);
            child=builder.start();
            if(!child.waitFor(25,TimeUnit.SECONDS)) {
                child.destroyForcibly();
                return "KERNIX_C3D6_CHILD_WATCHDOG_TIMEOUT_FAIL_CLOSED";
            }
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            try(InputStream pipe=child.getInputStream()) {
                byte[] buf=new byte[512]; int n;
                while((n=pipe.read(buf))!=-1) {
                    if(out.size()+n>2048)
                        return "KERNIX_C3D6_UNBOUNDED_CHILD_OUTPUT_REJECTED";
                    out.write(buf,0,n);
                }
            }
            String result=new String(out.toByteArray(),StandardCharsets.UTF_8).trim();
            if(child.exitValue()!=0)
                return "KERNIX_C3D6_FAIL_CLOSED exit="+child.exitValue()+"\n"+result;
            String[] lines=result.split("\\R");
            String[] expectedLines={
                MARKER,
                "NATIVE_KERNEL_PAGE_BYTES=4096",
                "ORIGINAL_GUEST_4K_PAGES=609",
                "SOURCE_TRIPLE_SHA256_VERIFIED=1",
                "ORIGINAL_4096_BYTE_PAGES_COMPARED=609",
                "GUEST_VA_TO_HOST_VA_METADATA_MAINTAINED=1",
                "HOST_KERNEL_CHOSEN_VA_WINDOW=1",
                "ORIGINAL_FIXED_GUEST_VA_MAPPED=0",
                "NATIVE_RO_PAGES_RELEASED=1",
                "FEX_EXECUTED=0",
                "LINUX_LDSO_EXECUTED=0",
                "WINDOWS_PE_EXECUTED=0"
            };
            if(lines.length!=expectedLines.length)
                return "KERNIX_C3D6_UNEXPECTED_RESULT_PROTOCOL_REJECTED";
            for(int i=0;i<lines.length;++i)
                if(!expectedLines[i].equals(lines[i]))
                    return "KERNIX_C3D6_UNEXPECTED_RESULT_PROTOCOL_REJECTED";
            return "نجح فحص حجز صفحات Linux بنافذة اختارها أندرويد.\n"+
                "الصفحات تحررت بعد المقارنة، ولم يتم تشغيل FEX أو Wine.\n\n"+result;
        } finally {
            if(child!=null)child.destroyForcibly();
        }
    }
    private void startTest() {
        if(!running.compareAndSet(false,true))return;
        button.setEnabled(false);
        status.setText("يجري فحص الذاكرة داخل عملية منفصلة...");
        new Thread(()->{
            String result;
            try { result=execute(); }
            catch(Exception failure) {
                result="KERNIX_C3D6_SAFE_FAILURE: "+
                       failure.getClass().getSimpleName()+
                       ": "+failure.getMessage();
            } finally {
                running.set(false);
            }
            final String output=result;
            runOnUiThread(()->{
                status.setText(output);
                button.setEnabled(true);
            });
        },"kernix-c3d6-native-ro").start();
    }
}
