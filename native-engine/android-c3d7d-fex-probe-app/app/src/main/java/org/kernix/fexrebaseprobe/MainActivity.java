package org.kernix.fexrebaseprobe;

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

// Opt-in, independently packaged original FEX x86 instruction execution.
/// Original Linux x86 main/ld-linux/libc remain DATA ONLY.
 // NO original guest ELF RIP, dynamic linker, Wine or games.
public final class MainActivity extends Activity {
    private static final String CHILD="libkernix_g2ec3d7d_exec_child.so";
    private static final String FLAG=
        "--kernix-c3d7d-rebased-fex-original-x86-memory-v1";
    private static final String MARKER=
        "KERNIX_G2EC3D7D_ANDROID_FEX_REBASED_X86_ELF_STACK_LOAD_STORE_PASS";
    private static final String ROOT="c3d7d-root";
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
        title.setText("KERNIX / C3-D7D");
        title.setGravity(Gravity.CENTER);
        title.setTextSize(24);
        title.setTextColor(Color.WHITE);
        layout.addView(title);
        TextView explanation=new TextView(this);
        explanation.setText("فحص تنفيذي اختياري ومحدود لـ FEXCore على أندرويد 4KB.\n"+
            "يحجز مواقع ذاكرة آمنة لملفات Linux الأصلية وStack المعاد تموضعها. "+
            "يشغّل تعليمات x86 قصيرة تقرأ منها وتكتب الناتج عبر FEX الحقيقي.\n"+
            "لا يشغّل ld-linux أو Wine أو الألعاب. إذا منع النظام JIT فالفحص يفشل بأمان. "+
            "لا يغيّر KERNIX v0.27 أو بيانات الألعاب.");
        explanation.setTextColor(Color.rgb(218,231,245));
        explanation.setTextSize(16);
        explanation.setPadding(0,24,0,24);
        layout.addView(explanation);
        button=new Button(this);
        button.setText("بدء فحص تنفيذ FEX الحقيقي C3-D7D");
        button.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX C3-D7D")
            .setMessage("هل توافق على تشغيل تعليمات x86 اختبارية محدودة بواسطة FEXCore "+
                "داخل عملية أندرويد منفصلة، مدة لا تتجاوز 25 ثانية، "+
                "دون تشغيل ld-linux أو Wine أو أي لعبة؟")
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
            Path temp=Files.createTempFile(dir,"c3d7d-", ".stage");
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
        Path fex=libRoot.resolve("libFEXCore.so");
        if(Files.isSymbolicLink(fex) ||
           !Files.isRegularFile(fex,LinkOption.NOFOLLOW_LINKS) ||
           !fex.toRealPath().getParent().equals(libRoot))
            throw new IOException("FEXCORE_LIBRARY_PATH_REJECTED");
        String fexDigest;
        try(InputStream in=getAssets().open("fexcore.sha256")) {
            byte[] bytes=in.readAllBytes();
            if(bytes.length>128)throw new IOException("FEXCORE_DIGEST_TOO_LONG");
            fexDigest=new String(bytes,StandardCharsets.US_ASCII).trim();
        }
        if(!fexDigest.matches("[0-9a-f]{64}") ||
           !sha256(fex).equals(fexDigest))
            throw new IOException("SIGNED_FEXCORE_SHA256_REJECTED");
        Path guest=prepareGuest();
        Process child=null;
        try {
            ProcessBuilder builder=new ProcessBuilder(
                runner.toRealPath().toString(), FLAG, guest.toString());
            builder.directory(getFilesDir());
            builder.environment().clear();
            builder.environment().put("LD_LIBRARY_PATH",libRoot.toString());
            builder.redirectErrorStream(true);
            child=builder.start();
            if(!child.waitFor(25,TimeUnit.SECONDS)) {
                child.destroyForcibly();
                return "KERNIX_C3D7D_CHILD_WATCHDOG_TIMEOUT_FAIL_CLOSED";
            }
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            try(InputStream pipe=child.getInputStream()) {
                byte[] buf=new byte[512]; int n;
                while((n=pipe.read(buf))!=-1) {
                    if(out.size()+n>16384)
                        return "KERNIX_C3D7D_UNBOUNDED_CHILD_OUTPUT_REJECTED";
                    out.write(buf,0,n);
                }
            }
            String result=new String(out.toByteArray(),StandardCharsets.UTF_8).trim();
            if(child.exitValue()!=0)
                return "KERNIX_C3D7D_FAIL_CLOSED exit="+child.exitValue()+"\n"+result;
            // FEXCore can emit independent diagnostics before the success
            // protocol. A success marker must be unique, and the exact
            // signed child result tail must match in full.
            final int start=result.indexOf(MARKER);
            if(start<0 || start!=result.lastIndexOf(MARKER))
                return "KERNIX_C3D7D_SUCCESS_MARKER_NOT_UNIQUE_OR_ABSENT\\n"+result;
            String[] lines=result.substring(start).trim().split("\\R");
            String[] expectedLines={
                MARKER,
                "NATIVE_KERNEL_PAGE_BYTES=4096",
                "ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1",
                "ORIGINAL_THREE_PIE_MODULES_REBASED=1",
                "REBASED_LINUX_X86_STACK_AUXV=1",
                "KERNEL_CHOSEN_CANONICAL_GUEST_VAS=1",
                "ACTUAL_FEX_X86_ELF_DATA_LOAD=1",
                "ACTUAL_FEX_X86_STACK_DATA_LOAD=1",
                "ACTUAL_FEX_X86_GUEST_STORE=1",
                "FEX_CPU_RAX_MATCHED=1",
                "NATIVE_GUEST_PAGES_READONLY=1",
                "MEMORY_WINDOWS_RELEASED=1",
                "ORIGINAL_LINUX_LDSO_EXECUTED=0",
                "ORIGINAL_ELF_GUEST_RIP_EXECUTED=0",
                "WINE_OR_WINDOWS_PE_EXECUTED=0"
            };
            if(lines.length!=expectedLines.length)
                return "KERNIX_C3D7D_UNEXPECTED_RESULT_PROTOCOL_REJECTED";
            for(int i=0;i<lines.length;++i)
                if(!expectedLines[i].equals(lines[i]))
                    return "KERNIX_C3D7D_UNEXPECTED_RESULT_PROTOCOL_REJECTED";
            return "نجح اختبار تعليمات x86 الحقيقية بواسطة FEX على أندرويد.\n"+
                "تمت قراءة ELF والـStack وكتابة الناتج وفحص RAX. "+
                "لم يتم تشغيل Linux ld-linux أو Wine أو الألعاب.\n\n"+
                result.substring(start).trim();
        } finally {
            if(child!=null)child.destroyForcibly();
        }
    }
    private void startTest() {
        if(!running.compareAndSet(false,true))return;
        button.setEnabled(false);
        status.setText("يجري اختبار FEX التنفيذي في عملية مستقلة...");
        new Thread(()->{
            String result;
            try { result=execute(); }
            catch(Exception failure) {
                result="KERNIX_C3D7D_SAFE_FAILURE: "+
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
        },"kernix-c3d7d-native-ro").start();
    }
}
