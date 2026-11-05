package org.kernix.originalfexldso21;

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
    private static final String CHILD="libkernix_g2ec3d8c3_ldso_twentyone_fex_child.so";
    private static final String FLAG=
        "--kernix-c3d8c3-source-original-ldso-21-instructions-v1";
    private static final String MARKER=
        "KERNIX_C3D8C3_ANDROID_DEVICE_SOURCE_ORIGINAL_LDSO_21_FEX_INSTRUCTIONS_PASS";
    private static final String ROOT="c3d8c3-original-guest";
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
        title.setText("KERNIX / C3-D8C3");
        title.setGravity(Gravity.CENTER);
        title.setTextSize(24);
        title.setTextColor(Color.WHITE);
        layout.addView(title);
        TextView explanation=new TextView(this);
        explanation.setText("فحص مستقل لتنفيذ 21 تعليمة x86 أصلية من محمّل Linux عبر FEX على أندرويد.\n"+
            "بعد 18 تعليمة مثبتة سابقاً، يختبر RDTSC وتحديث بايت واحد في ذاكرة الضيف RW "+
            "وتعليمة LEA RSI بعنوان محمّل Linux الأصلي.\n"+
            "يعيد بايت الذاكرة و192 بايت من الـStack إلى وضعها قبل الفحص ويتوقف قبل التعليمة 22. "+
            "لا يشغّل المحمّل كاملاً أو Wine أو الألعاب. ولا يغيّر KERNIX v0.27.");
        explanation.setTextColor(Color.rgb(218,231,245));
        explanation.setTextSize(16);
        explanation.setPadding(0,24,0,24);
        layout.addView(explanation);
        button=new Button(this);
        button.setText("فحص 21 تعليمة أصلية بواسطة FEX C3-D8C3");
        button.setOnClickListener(v->new AlertDialog.Builder(this)
            .setTitle("KERNIX C3-D8C3")
            .setMessage("هل توافق على تشغيل 21 تعليمة أصلية من ld-linux داخل عملية مستقلة "+
                "بحد 25 ثانية؟ يشمل الفحص RDTSC وكتابة بايت واحد في ذاكرة ضيف مؤقتة "+
                "مع استعادتها. هذا ليس تشغيل glibc كاملاً أو Wine أو ألعاب.")
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
            Path temp=Files.createTempFile(dir,"c3d8c3-", ".stage");
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
            return "KERNIX_C3D8C3_NATIVE_TRACE_TOO_LARGE_FAIL_CLOSED";
        if(size<=0)return "KERNIX_C3D8C3_NO_NATIVE_TRACE";
        final int count=(int)Math.min(size,16384L);
        byte[] bytes=new byte[count];
        try(java.io.RandomAccessFile file=new java.io.RandomAccessFile(trace,"r")) {
            file.seek(size-count);
            file.readFully(bytes);
        }
        String result=new String(bytes,StandardCharsets.UTF_8).trim();
        if(size>count)
            return "KERNIX_C3D8C3_NATIVE_TRACE_TRUNCATED_TO_LAST_16384_BYTES\n"+result;
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
        File trace=File.createTempFile("c3d8c3-fex-",".log",getCacheDir());
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
                return "KERNIX_C3D8C3_ANDROID_CHILD_WATCHDOG_TIMEOUT_FAIL_CLOSED\n"+
                    traceTail(trace);
            }
            String result=traceTail(trace);
            if(result.startsWith("KERNIX_C3D8C3_NATIVE_TRACE_TOO_LARGE"))
                return result;
            if(child.exitValue()!=0)
                return "KERNIX_C3D8C3_ANDROID_DEVICE_FAIL_CLOSED exit="+
                    child.exitValue()+"\n"+result;
            final int from=result.indexOf(MARKER);
            if(from<0 || from!=result.lastIndexOf(MARKER))
                return "KERNIX_C3D8C3_SUCCESS_MARKER_NOT_UNIQUE_OR_ABSENT\n"+result;
            String[] lines=result.substring(from).trim().split("\\R");
            String[] expectedLines={
                MARKER,
                "ORIGINAL_THREE_X86_LINUX_ELF_SHA256_VERIFIED=1",
                "REAL_ANDROID_BIONIC_ARM64_FEX_CONTEXT_CREATED=1",
                "ORIGINAL_FIRST_EIGHTEEN_SOURCE_X86_OPS_VERIFIED=1",
                "ORIGINAL_NINETEENTH_RDTSC_EXECUTED=1",
                "GUEST_RDTSC_EAX_EDX_32BIT_RESULT_VERIFIED=1",
                "GUEST_COMBINED_TSC_NONZERO=1",
                "ORIGINAL_TWENTIETH_AND_GUEST_RW_DATA_EXECUTED=1",
                "ORIGINAL_AND_SOURCE_DERIVED_RW_ADDRESS_VERIFIED=1",
                "ORIGINAL_AND_RW_BIT5_CLEARED_OTHER_BITS_PRESERVED=1",
                "ORIGINAL_TWENTY_FIRST_LEA_RSI_EXECUTED=1",
                "ORIGINAL_LEA_RSI_REBASED_LOADER_POINTER_VERIFIED=1",
                "ORIGINAL_SEVEN_CALL_PUSH_STACK_WITNESSES_VERIFIED=1",
                "ORIGINAL_GUEST_MOVAPS_AND_LOCAL_RDI_VERIFIED=1",
                "ORIGINAL_GUEST_RW_DATA_BYTE_RESTORED=1",
                "SOURCE_TWENTY_SECOND_MOV_R8D_REPLACED_BY_BOUNDED_HLT=1",
                "SOURCE_TWENTY_SECOND_MOV_R8D_EXECUTED=0",
                "SOURCE_GUEST_192_STACK_AND_HOST_STACK_RESTORED=1",
                "ORIGINAL_THREE_FILE_BACKED_PTLOAD_BYTES_RESTORED=1",
                "ORIGINAL_PTLOAD_RX_RW_WX_ENFORCED=1",
                "ALL_ORIGINAL_GUEST_WINDOWS_RELEASED=1",
                "GUEST_LINUX_SYSCALLS_FORWARDED=0",
                "COMPLETE_LDSO_DYNAMIC_LINKER_STARTUP=0",
                "WINE_OR_WINDOWS_PE_EXECUTED=0"
            };
            if(lines.length!=expectedLines.length)
                return "KERNIX_C3D8C3_UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED\n"+result;
            for(int i=0;i<lines.length;++i)
                if(!expectedLines[i].equals(lines[i]))
                    return "KERNIX_C3D8C3_UNEXPECTED_DEVICE_RESULT_PROTOCOL_REJECTED\n"+
                        result;
            return "نجح تنفيذ 21 تعليمة أصلية من ld-linux بواسطة FEX على أندرويد.\n"+
                "تم التحقق من توقيت RDTSC وكتابة بيانات RW وتعليمة LEA RSI، واستعادة المصدر والستاك.\n"+
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
                result="KERNIX_C3D8C3_SAFE_FAILURE: "+
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
        },"kernix-c3d8c3-memory-preflight").start();
    }
}
