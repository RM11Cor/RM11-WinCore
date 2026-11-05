package org.kernix.originalfexldso18;

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
// Original Linux x86 main/ld-linux/libc remain hash-verified app-private data.
// Bounded REAL source-authentic guest ld-linux x86 RIP is executed by FEX
// only on explicit opt-in, NOT complete glibc startup, Wine or games.
public final class MainActivity extends Activity {
    private static final String CHILD="libkernix_g2ec3d8c2_ldso_eighteen_fex_child.so";
    private static final String FLAG=
        "--kernix-c3d8c2-source-original-ldso-eighteen-instructions-v1";
    private static final String MARKER=
        "KERNIX_C3D8C2_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_EIGHTEEN_FEX_INSTRUCTIONS_PASS";
    private static final String ROOT="c3d8c2-original-guest";
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
        title.setText("KERNIX / C3-D8C2");
        title.setGravity(Gravity.CENTER);
        title.setTextSize(24);
        title.setTextColor(Color.WHITE);
        layout.addView(title);
        TextView explanation=new TextView(this);
        explanation.setText("اختبار مستقل لـ18 تعليمة x86 أصلية من محمّل Linux بواسطة FEX على أندرويد.\n"+
            "يتحقق من 5 تعليمات PUSH الإضافية، وحجز 136 بايت للمتغيرات المحلية، "+
            "وحفظ سجل RDI و128 بت XMM1 داخل Stack بطول 192 بايت.\n"+
            "يتوقف قبل تعليمة RDTSC التاسعة عشرة. لا يشغّل المحمّل كاملاً أو Wine أو الألعاب. "+
            "ولا يغيّر KERNIX v0.27 أو ملفات ألعابك.");
        explanation.setTextColor(Color.rgb(218,231,245));
        explanation.setTextSize(16);
        explanation.setPadding(0,24,0,24);
        layout.addView(explanation);
        button=new Button(this);
        button.setText("فحص 18 تعليمة أصلية بواسطة FEX C3-D8C2");
        button.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX C3-D8C2")
            .setMessage("هل توافق على تشغيل 18 تعليمة أصلية من ld-linux بواسطة FEX "+
                "داخل عملية منفصلة لمدة لا تتجاوز 25 ثانية؟ يُختبر الـStack وMOVAPS "+
                "ولا يتم تشغيل المحمّل كاملاً أو الألعاب.")
            .setNegativeButton("إلغاء",(di,w)->{})
            .setPositiveButton("بدء الفحص",(di,w)->startTest())
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
            Path temp=Files.createTempFile(dir,"c3d8c2-", ".stage");
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
    // Bound output even if FEX crashes, writes too much text, or times out.
    // A redirected app-private file prevents the classic waitFor() +
    // undrained native stdout pipe deadlock.
    private static String traceTail(File trace) throws IOException {
        final long size=trace.length();
        if(size>1024L*1024L)
            return "KERNIX_C3D8C2_NATIVE_TRACE_TOO_LARGE_FAIL_CLOSED";
        if(size<=0)return "KERNIX_C3D8C2_NO_NATIVE_TRACE";
        final int count=(int)Math.min(size,16384L);
        byte[] bytes=new byte[count];
        try(java.io.RandomAccessFile file=new java.io.RandomAccessFile(trace,"r")) {
            file.seek(size-count);
            file.readFully(bytes);
        }
        String result=new String(bytes,StandardCharsets.UTF_8).trim();
        if(size>count)
            return "KERNIX_C3D8C2_NATIVE_TRACE_TRUNCATED_TO_LAST_16384_BYTES\n"+result;
        return result;
    }
    private String execute() throws Exception {
        Path libRoot=new File(getApplicationInfo().nativeLibraryDir)
                .toPath().toRealPath();
        Path runner=libRoot.resolve(CHILD);
        if(Files.isSymbolicLink(runner) ||
           !Files.isRegularFile(runner,LinkOption.NOFOLLOW_LINKS) ||
           !runner.toRealPath().getParent().equals(libRoot) ||
           !Files.isExecutable(runner))
           throw new IOException("SIGNED_NATIVE_CHILD_INVALID");
        String expected;
        try(InputStream in=getAssets().open("runner.sha256")) {
            byte[] bytes=in.readAllBytes();
            if(bytes.length>128)throw new IOException("RUNNER_DIGEST_TOO_LONG");
            expected=new String(bytes,StandardCharsets.US_ASCII).trim();
        }
        if(!expected.matches("[0-9a-f]{64}") ||
           !sha256(runner).equals(expected))
           throw new IOException("SIGNED_NATIVE_CHILD_SHA256_REJECTED");
        Path core=libRoot.resolve("libFEXCore.so");
        if(Files.isSymbolicLink(core) ||
           !Files.isRegularFile(core,LinkOption.NOFOLLOW_LINKS) ||
           !core.toRealPath().getParent().equals(libRoot))
            throw new IOException("PINNED_FEXCORE_PATH_REJECTED");
        String expectedCore;
        try(InputStream in=getAssets().open("fexcore.sha256")) {
            byte[] bytes=in.readAllBytes();
            if(bytes.length>128)throw new IOException("FEXCORE_DIGEST_TOO_LONG");
            expectedCore=new String(bytes,StandardCharsets.US_ASCII).trim();
        }
        if(!expectedCore.matches("[0-9a-f]{64}") ||
           !sha256(core).equals(expectedCore))
            throw new IOException("PINNED_FEXCORE_SHA256_REJECTED");
        Path guest=prepareGuest();
        Process child=null;
        File trace=File.createTempFile("c3d8c2-fex-",".log",getCacheDir());
        Os.chmod(trace.getAbsolutePath(),0600);
        try {
            ProcessBuilder builder=new ProcessBuilder(
                runner.toRealPath().toString(),FLAG,guest.toString());
            builder.directory(getFilesDir());
            builder.environment().clear();
            builder.environment().put("LD_LIBRARY_PATH",libRoot.toString());
            builder.redirectErrorStream(true);
            builder.redirectOutput(trace);
            child=builder.start();
            if(!child.waitFor(25,TimeUnit.SECONDS)) {
                child.destroyForcibly();
                child.waitFor(3,TimeUnit.SECONDS);
                return "KERNIX_C3D8C2_ANDROID_CHILD_WATCHDOG_TIMEOUT_FAIL_CLOSED\n"+
                    traceTail(trace);
            }
            String result=traceTail(trace);
            if(result.startsWith("KERNIX_C3D8C2_NATIVE_TRACE_TOO_LARGE"))
                return result;
            if(child.exitValue()!=0)
                return "KERNIX_C3D8C2_ANDROID_DEVICE_FAIL_CLOSED exit="+
                    child.exitValue()+"\n"+result;
            final int from=result.indexOf(MARKER);
            if(from<0 || from!=result.lastIndexOf(MARKER))
                return "KERNIX_C3D8C2_SUCCESS_MARKER_NOT_UNIQUE_OR_ABSENT\n"+result;
            String[] lines=result.substring(from).trim().split("\\R");
            String[] expectedLines={
                MARKER,
                "ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1",
                "REAL_ANDROID_BIONIC_ARM64_FEX_CONTEXT_CREATED=1",
                "ORIGINAL_LDSO_FIRST_TEN_SOURCE_X86_LEA_SIMD_OPS_VERIFIED=1",
                "ORIGINAL_LDSO_SOURCE_GPR_PUSH_R15_EXECUTED=1",
                "ORIGINAL_LDSO_SOURCE_GPR_PUSH_R14_EXECUTED=1",
                "ORIGINAL_LDSO_SOURCE_GPR_PUSH_R13_EXECUTED=1",
                "ORIGINAL_LDSO_SOURCE_GPR_PUSH_R12_EXECUTED=1",
                "ORIGINAL_LDSO_SOURCE_GPR_PUSH_RBX_EXECUTED=1",
                "ORIGINAL_SEVEN_CALL_PUSH_STACK_SLOTS_AND_VALUES_VERIFIED=1",
                "ORIGINAL_SOURCE_SUB_RSP_0X88_FRAME_EXECUTED=1",
                "ORIGINAL_SOURCE_MOV_GUEST_LOCAL_RDI_EXECUTED=1",
                "ORIGINAL_SOURCE_MOVAPS_GUEST_LOCAL_XMM1_EXECUTED=1",
                "ORIGINAL_LOCAL_RDI_AND_PACKED_SSE_LANES_VERIFIED=1",
                "ORIGINAL_MOVAPS_GUEST_LOCAL_ALIGNMENT_16_VERIFIED=1",
                "GUEST_RSP_EQUALS_ORIGINAL_RSP_MINUS_192=1",
                "SOURCE_NINETEENTH_RDTSC_REPLACED_BY_BOUNDED_HLT=1",
                "SOURCE_NINETEENTH_RDTSC_EXECUTED=0",
                "SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1",
                "ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1",
                "ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1",
                "GUEST_LINUX_SYSCALLS_FORWARDED=0",
                "COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",
                "WINE_OR_WINDOWS_PE_EXECUTED=0"
            };
            if(lines.length!=expectedLines.length)
                return "KERNIX_C3D8C2_UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED\n"+result;
            for(int i=0;i<lines.length;++i)
                if(!expectedLines[i].equals(lines[i]))
                    return "KERNIX_C3D8C2_UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED\n"+
                        result;
            return "نجح تنفيذ 18 تعليمة أصلية من ld-linux بواسطة FEX على أندرويد.\n"+
                "تم التحقق من تعليمات PUSH والـStack بطول 192 بايت وكتابة MOVAPS واستعادة الذاكرة.\n"+
                "لم يتم تشغيل المحمّل كاملاً أو Wine أو الألعاب.\n\n"+
                result.substring(from).trim();
        } finally {
            if(child!=null && child.isAlive())child.destroyForcibly();
            if(!trace.delete())trace.deleteOnExit();
        }
    }
    private void startTest() {
        if(!running.compareAndSet(false,true))return;
        button.setEnabled(false);
        status.setText("يجري تنفيذ تعليمات x86 أصلية بواسطة FEX في عملية مستقلة...");
        new Thread(()->{
            String result;
            try { result=execute(); }
            catch(Exception failure) {
                result="KERNIX_C3D8C2_SAFE_FAILURE: "+
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
        },"kernix-c3d8c2-memory-preflight").start();
    }
}
