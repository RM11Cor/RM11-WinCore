package com.r4.carxpc;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Locale;

/** Second, explicitly launched diagnostic icon. Normal CarX UI stays intact.
 *  No FEX execution ever occurs in this Activity or its process.
 */
public final class R3D4ProbeActivity extends Activity {
    private TextView output;
    private Button run;
    private long sessionNonce;
    private boolean running;
    private String lastReport;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private static final long INSPECT_AFTER_MS = 7800L;
    private static final long LOADER_BIAS = 0x0000004100000000L;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        setTitle("CarX R3D4 | FEX / Wine 07D");
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(36, 44, 36, 24);
        output = new TextView(this);
        output.setTextSize(17);
        output.setText("07D: NOT_TESTED\nاختبار منفصل للمحمّل الحقيقي. لا يشغّل اللعبة ولا يعدّل ملفاتها.");
        layout.addView(output);
        run = new Button(this);
        run.setText("تشغيل اختبار 07D المعزول");
        layout.addView(run);
        Button share = new Button(this);
        share.setText("مشاركة التقرير");
        layout.addView(share);
        setContentView(layout);
        run.setOnClickListener(v -> startProbe());
        share.setOnClickListener(v -> {
            if (lastReport == null) return;
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_TEXT, lastReport);
            startActivity(Intent.createChooser(send, "مشاركة تقرير R3D4"));
        });
    }

    private void startProbe() {
        if (running) return;
        running = true; run.setEnabled(false);
        sessionNonce = new SecureRandom().nextLong() & Long.MAX_VALUE;
        if (sessionNonce == 0) sessionNonce = 1;
        lastReport = null;
        File f = new File(getFilesDir(), R3D4ProbeService.EVIDENCE_FILE);
        if (f.exists() && !f.delete()) {
            running = false; run.setEnabled(true);
            output.setText("REJECTED: لم يمكن مسح أثر جلسة قديمة");
            return;
        }
        output.setText("07D: RUNNING\nالتنفيذ داخل عملية منفصلة مع مهلة قتل 6 ثوانٍ...");
        try {
            Intent intent = new Intent(this, R3D4ProbeService.class);
            intent.putExtra("r3d4_nonce", sessionNonce);
            startService(intent);
        } catch (Throwable t) {
            output.setText("07D: START_SERVICE_FAILED (" +
                t.getClass().getSimpleName() + ")");
        }
        final long expectedNonce = sessionNonce;
        handler.postDelayed(() -> inspect(expectedNonce), INSPECT_AFTER_MS);
    }

    private void inspect(long expectedNonce) {
        if (sessionNonce != expectedNonce) return;
        running = false;run.setEnabled(true);
        String state = "NOT_OBSERVED";
        JSONObject report = new JSONObject();
        try {
            report.put("schema","r4.carx.r3d4.first-syscall-device-report.v1");
            report.put("stage","07D_WINE_LDSO_FIRST_FEX_SYSCALL");
            report.put("device_process_isolated",true);
            report.put("parent_did_not_execute_fex",true);
            report.put("timeout_ms",6000);
            report.put("session_nonce",Long.toUnsignedString(expectedNonce));
            report.put("wine_process_fully_started",false);
            report.put("win64_pe_executed",false);
            report.put("carx_game_boot_proven",false);
            File file=new File(getFilesDir(),R3D4ProbeService.EVIDENCE_FILE);
            if (file.isFile()) {
                byte[] data=Files.readAllBytes(file.toPath());
                if (data.length==56) {
                    ByteBuffer bb=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
                    int magic=bb.getInt(),version=bb.getInt();
                    long nonce=bb.getLong(), syscall=bb.getLong(),
                         opcode=bb.getLong(),callback=bb.getLong(),offset=bb.getLong();
                    int interpretation=bb.getInt(), reserved=bb.getInt();
                    boolean valid=magic==0x33443352 && version==2 &&
                        nonce==expectedNonce && syscall<=0xFFFFFFFFL &&
                        opcode>=LOADER_BIAS && opcode-LOADER_BIAS<0x1000000L &&
                        offset<0x200000L && reserved==0 &&
                        ((interpretation==1 && callback==opcode) ||
                         (interpretation==2 && callback==opcode+2));
                    if (valid) {
                        state="OBSERVED_SOURCE_LOCKED_X86_SYSCALL_IN_FEX_CALLBACK";
                        report.put("syscall_number",syscall);
                        report.put("syscall_opcode_rip",String.format(Locale.ROOT,
                            "0x%016x",opcode));
                        report.put("callback_rip",String.format(Locale.ROOT,
                            "0x%016x",callback));
                        report.put("source_ldso_file_offset",offset);
                        report.put("rip_interpretation",interpretation);
                    } else state="REJECTED_INVALID_WITNESS";
                } else if (data.length!=0) state="REJECTED_TRUNCATED_WITNESS";
            }
            report.put("status",state);
            report.put("evidence_limit",
                "Only original GNU ld.so first x86 Linux syscall, if witnessed. Not Wine startup, PE, DXVK or gameplay.");
            lastReport=report.toString(2);
            output.setText("07D: "+state+"\n\n"+lastReport);
        } catch (Throwable t) {
            output.setText("07D: REPORT_REJECTED "+t.getClass().getSimpleName());
        }
    }
}
