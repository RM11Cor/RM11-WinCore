package com.rm11.wincore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Arabic-first, offline diagnostic shell targeted at one device model. */
public final class MainActivity extends Activity {
    private static final int IMPORT_BASE = 180;
    private static final int REPORT_EXPORT = 360;
    private static final int INSPECT_PE = 480;
    private static final int VERIFY_ENGINE_BUNDLE = 580;
    private static final int GAME_PROFILE_PICK = 590;
    private static final int GAME_PROFILE_EXPORT = 591;
    private static final int ELF_RUNTIME_PICK = 595;
    private static final int STAGE_ENGINE_BUNDLE = 596;
    private static final int BG = Color.rgb(8, 13, 24);
    private static final int SURFACE = Color.rgb(18, 28, 43);
    private static final int MUTED = Color.rgb(166, 181, 199);
    private static final int MINT = Color.rgb(62, 225, 188);
    private static final int WHITE = Color.rgb(239, 244, 252);
    private LinearLayout content;
    private TextView reportView;
    private Button scanButton;
    private Button preflightButton;
    private TextView preflightView;
    private TextView runtimeV03View;
    private TextView engineBundleStatusView;
    private TextView elfRuntimeStatusView;
    private TextView nativeBridgeStatusView;
    private TextView adapterStatusView;
    private TextView stagedBundleStatusView;
    private TextView stagedAuditView;
    private TextView processExecStatusView;
    private TextView officialBox64StatusView;
    private TextView box64GuestStatusView;
    private TextView box64DynamicStatusView;
    private TextView box64V16StatusView;
    private TextView box64V17StatusView;
    private TextView box64V18StatusView;
    private TextView box64V19StatusView;
    private TextView wineV20StatusView;
    private TextView wineV22StatusView;
    private Button wineV22Button;
    private Button wineV233BootButton;
    private Button wineV22HeapButton;
    private Button wineV22MallocButton;
    private TextView wineV21StatusView;
    private Button wineV21Button;
    private Button wineV20Button;
    private Button box64V19Button;
    private TextView gameProfileView;
    private String gameProfile = "لم يتم فحص ملف لعبة بعد.";
    private String report = "لم يتم فحص الجهاز بعد. اضغط «فحص الهاتف الآن».";
    private final Map<String, TextView> installerStatusViews = new HashMap<>();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
    }

    private int dp(float n) { return (int) (n * getResources().getDisplayMetrics().density + 0.5f); }

    private GradientDrawable shape(int color, int radius) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(color);
        gd.setCornerRadius(dp(radius));
        return gd;
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setGravity(Gravity.START);
        t.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        t.setPadding(0, dp(3), 0, dp(3));
        return t;
    }

    private LinearLayout column() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        return l;
    }

    private void addSpace(LinearLayout p, int dpHeight) {
        View spacer = new View(this);
        p.addView(spacer, new LinearLayout.LayoutParams(1, dp(dpHeight)));
    }

    private LinearLayout card(String heading) {
        LinearLayout box = column();
        box.setPadding(dp(17), dp(16), dp(17), dp(16));
        box.setBackground(shape(SURFACE, 18));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.bottomMargin = dp(12);
        content.addView(box, params);
        if (!TextUtils.isEmpty(heading)) {
            box.addView(text(heading, 18, WHITE, true));
            addSpace(box, 6);
        }
        return box;
    }

    private Button button(String label, boolean primary, View.OnClickListener listener) {
        Button b = new Button(this);
        b.setAllCaps(false);
        b.setText(label);
        b.setTextSize(14);
        b.setTextColor(primary ? BG : WHITE);
        b.setBackground(shape(primary ? MINT : Color.rgb(42, 58, 77), 12));
        b.setPadding(dp(12), dp(8), dp(12), dp(8));
        b.setMinHeight(dp(46));
        b.setOnClickListener(listener);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(8);
        b.setLayoutParams(params);
        return b;
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        scroll.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        content = column();
        content.setPadding(dp(16), dp(22), dp(16), dp(36));
        scroll.addView(content);
        setContentView(scroll);

        content.addView(text("RM11 WinCore", 32, MINT, true));
        content.addView(text("REDMAGIC 11 PRO  •  16GB / 512GB", 14, WHITE, true));
        content.addView(text("V2.3.5 — اختبار إقلاع Wine المحسّن", 13, MUTED, false));
        addSpace(content, 18);

        LinearLayout intro = card("بداية المشروع");
        intro.addView(text("نجحت الاختبارات الأربع لبرامج Linux x86-64 عبر Box64 على هاتفك في V1.9. في V2.1.4 نجح wine64 --version على الهاتف. V2.3.5 تعيد اختبار تهيئة Wine عن تنفيذ ملف Windows PE حقيقي آمن من صنع المشروع للتحقق من وظائف Win32 والملفات؛ لا تتوقع تشغيل الألعاب أو البرامج الخارجية بعد.", 14, MUTED, false));
        intro.addView(text("✓ فحص العتاد    ✓ فحص Vulkan    ✓ ملفات EXE    ✓ تقرير قابل للمشاركة", 13, MINT, false));

        LinearLayout diag = card("01  •  فحص جهاز REDMAGIC");
        diag.addView(text("سنقرأ معلومات الجهاز الحقيقية، الرام والتخزين وVulkan وحالة الحرارة. لا يتطلب روت أو تسجيل دخول.", 14, MUTED, false));
        scanButton = button("فحص الهاتف الآن", true, v -> runScan());
        diag.addView(scanButton);
        diag.addView(button("تصدير تقرير الفحص TXT", false, v -> exportReport()));
        reportView = text(report, 12, WHITE, false);
        reportView.setTextDirection(View.TEXT_DIRECTION_LTR);
        reportView.setGravity(Gravity.LEFT);
        reportView.setTextIsSelectable(true);
        reportView.setTypeface(Typeface.MONOSPACE);
        reportView.setPadding(dp(10), dp(10), dp(10), dp(10));
        reportView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        LinearLayout.LayoutParams reportParams = new LinearLayout.LayoutParams(-1, -2);
        reportParams.topMargin = dp(12);
        diag.addView(reportView, reportParams);

        LinearLayout readiness = card("02  •  جاهزية المحرك على هاتفك");
        readiness.addView(text("يفحص المطابقة مع NX809J والذاكرة والتخزين وميزات Vulkan الحقيقية. هذا لا يقوم بتثبيت Wine/Box64 ولا يشغّل EXE.", 14, MUTED, false));
        preflightButton = button("فحص جاهزية المحرك", true, v -> runPreflight());
        readiness.addView(preflightButton);
        preflightView = text("لم يتم فحص جاهزية المحرك بعد.", 12, WHITE, false);
        preflightView.setTextDirection(View.TEXT_DIRECTION_LTR);
        preflightView.setGravity(Gravity.LEFT);
        preflightView.setTextIsSelectable(true);
        preflightView.setTypeface(Typeface.MONOSPACE);
        preflightView.setPadding(dp(10), dp(10), dp(10), dp(10));
        preflightView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        readiness.addView(preflightView);

        LinearLayout bootstrap = card("03  •  تجهيز مساحة المحرك واختبار العمليات");
        bootstrap.addView(text("اختبار عملي جديد: ننشئ مجلدات خاصة بالتطبيق، نختبر تشغيل عملية أندرويد ARM64، ونفحص ترويسة EXE بدون تشغيلها. هذي مو بيئة Wine لحد الآن.", 14, MUTED, false));
        runtimeV03View = text("ما تم تشغيل اختبارات V0.3 بعد.", 12, WHITE, false);
        runtimeV03View.setTextDirection(View.TEXT_DIRECTION_LTR);
        runtimeV03View.setGravity(Gravity.LEFT);
        runtimeV03View.setTextIsSelectable(true);
        runtimeV03View.setTypeface(Typeface.MONOSPACE);
        runtimeV03View.setPadding(dp(10), dp(10), dp(10), dp(10));
        runtimeV03View.setBackground(shape(Color.rgb(11, 18, 29), 10));
        bootstrap.addView(button("1 — إنشاء مساحة المحرك المحلية", true, v -> runBootstrap(false)));
        bootstrap.addView(button("2 — اختبار تنفيذ عملية ARM64", false, v -> runBootstrap(true)));
        bootstrap.addView(button("3 — فحص بنية ملف Windows EXE", false, v -> choosePe()));
        bootstrap.addView(runtimeV03View);

        LinearLayout compatibility = card("04  •  RM11 Smart Balance — فحص لعبة تلقائياً");
        compatibility.addView(text("اختر ملف EXE أصلياً من لعبتك. نقرأ ترويسة PE وجدول استيراد DLL بصورة آمنة ونقترح دقة وهدف FPS مبدئيين لهاتفك، دون تشغيل اللعبة. هذا ليس كشفاً مضموناً لاسم اللعبة أو قياساً فعلياً للأداء.", 14, MUTED, false));
        compatibility.addView(button("تحليل EXE واقتراح توازن الرسوميات / FPS", true, v -> chooseGameForProfile()));
        compatibility.addView(button("تصدير مقترحات التوازن TXT", false, v -> exportGameProfile()));
        gameProfileView = text(gameProfile, 12, WHITE, false);
        gameProfileView.setTextDirection(View.TEXT_DIRECTION_LTR);
        gameProfileView.setGravity(Gravity.LEFT);
        gameProfileView.setTextIsSelectable(true);
        gameProfileView.setTypeface(Typeface.MONOSPACE);
        gameProfileView.setPadding(dp(10), dp(10), dp(10), dp(10));
        gameProfileView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        compatibility.addView(gameProfileView);

        LinearLayout engineAudit = card("05  •  تدقيق مكونات محرك V0.4");
        engineAudit.addView(text("اختر حزمة RM11 الخاصة بالمحرك وفق مخططنا، لفحص الملفات و SHA256 والمعمارية والتراخيص قراءةً فقط. لا تستخدم APK الخاص بـ Winlator أو ZIP المصدر: هذان ليسا حزمة محرك. لا يتم التثبيت أو التشغيل هنا.", 14, MUTED, false));
        engineAudit.addView(button("فحص حزمة مكونات المحرك (ZIP)", false, v -> chooseEngineBundle()));
        engineBundleStatusView = text("لم يتم اختيار حزمة محرك. Wine/Box64 غير مدمجين بعد.", 12, WHITE, false);
        engineBundleStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        engineBundleStatusView.setGravity(Gravity.LEFT);
        engineBundleStatusView.setTextIsSelectable(true);
        engineBundleStatusView.setTypeface(Typeface.MONOSPACE);
        engineBundleStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        engineBundleStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        engineAudit.addView(engineBundleStatusView);

        LinearLayout elfAudit = card("06  •  تدقيق ملفات Wine / Box64 الأصلية (ELF)");
        elfAudit.addView(text("اختر ملف ELF ثنائياً لمكوّن محرك مرخّص. سنفحص معمارية الملف ومحمّل Linux/Android وبعض المكتبات المطلوبة، دون تنفيذه أو نسخه. هذا الفحص لا يجعل Wine قابلاً للتشغيل بعد.", 14, MUTED, false));
        elfAudit.addView(button("فحص ملف ELF للمحرك", true, v -> chooseElfRuntime()));
        elfRuntimeStatusView = text("لم يتم فحص أي ملف ELF بعد. لا توجد مكونات Wine/Box64 مدمجة.", 12, WHITE, false);
        elfRuntimeStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        elfRuntimeStatusView.setGravity(Gravity.LEFT);
        elfRuntimeStatusView.setTextIsSelectable(true);
        elfRuntimeStatusView.setTypeface(Typeface.MONOSPACE);
        elfRuntimeStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        elfRuntimeStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        elfAudit.addView(elfRuntimeStatusView);

        LinearLayout nativeBridge = card("07  •  اختبار مكتبة ARM64 المدمجة (JNI)");
        nativeBridge.addView(text("نشغّل كود C++ أصلي من داخل APK نفسه ونفحص ذاكرة الصفحات وربط libc في أندرويد. هذا اختبار أساسي حقيقي لمسار JNI، وليس Wine أو Box64 أو تشغيل ألعاب.", 14, MUTED, false));
        nativeBridge.addView(button("تشغيل اختبار ARM64 الأصلي", true, v -> {
            if (!RuntimeBootstrap.correctDevice()) {
                nativeBridgeStatusView.setText("[STOP] هذا الاختبار مخصص لجهاز NX809J / Android 16.");
            } else {
                nativeBridgeStatusView.setText(NativeRuntimeBridge.inspect());
            }
        }));
        nativeBridgeStatusView = text("لم يتم تشغيل فحص مكتبة ARM64 بعد.", 12, WHITE, false);
        nativeBridgeStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        nativeBridgeStatusView.setGravity(Gravity.LEFT);
        nativeBridgeStatusView.setTextIsSelectable(true);
        nativeBridgeStatusView.setTypeface(Typeface.MONOSPACE);
        nativeBridgeStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        nativeBridgeStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        nativeBridge.addView(nativeBridgeStatusView);

        LinearLayout adapter = card("08  •  اختبار ربط وحدة ARM64 مستقلة");
        adapter.addView(text("نحمّل مكتبة ARM64 ثانية مضمّنة مع تطبيق RM11 باستخدام dlopen ونختبر نسخة ABI ودالة فعلية. هذا يثبت عمل نقطة الربط بين مكتباتنا فقط؛ لا يشغّل Wine أو Box64 ولا يحمّل ملفات خارجية.", 14, MUTED, false));
        adapter.addView(button("تشغيل اختبار ربط وحدة المحرك", true, v -> {
            if (!RuntimeBootstrap.correctDevice()) {
                adapterStatusView.setText("[STOP] الاختبار مخصص لجهاز NX809J / Android 16.");
            } else {
                adapterStatusView.setText(NativeRuntimeBridge.inspectAdapter());
            }
        }));
        adapterStatusView = text("لم يتم تشغيل اختبار ربط الوحدة بعد.", 12, WHITE, false);
        adapterStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        adapterStatusView.setGravity(Gravity.LEFT);
        adapterStatusView.setTextIsSelectable(true);
        adapterStatusView.setTypeface(Typeface.MONOSPACE);
        adapterStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        adapterStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        adapter.addView(adapterStatusView);

        LinearLayout stageBundle = card("09  •  حفظ مكونات المحرك بعد تدقيقها (V0.9)");
        stageBundle.addView(text("اختر حزمة RM11 Engine ZIP وفق المواصفات، ليتم التحقق من جميع الملفات وSHA256 ثم حفظها داخل مساحة التطبيق الخاصة كبيانات فقط. لا نُشغّل أي ملف منها، ولا نثبت Wine أو Box64. لا تختَر APK أو ZIP المصدر.", 14, MUTED, false));
        stageBundle.addView(button("فحص وحفظ حزمة المحرك", true, v -> chooseBundleToStage()));
        stagedBundleStatusView = text(EngineBundleStager.status(this), 12, WHITE, false);
        stagedBundleStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        stagedBundleStatusView.setGravity(Gravity.LEFT);
        stagedBundleStatusView.setTextIsSelectable(true);
        stagedBundleStatusView.setTypeface(Typeface.MONOSPACE);
        stagedBundleStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        stagedBundleStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        stageBundle.addView(stagedBundleStatusView);

        LinearLayout inventory = card("10  •  تدقيق الحزمة المحفوظة وملفات ELF (V1.0)");
        inventory.addView(text("نفحص مكونات ZIP التي حفظتها مسبقاً في القسم 09: نعيد حساب SHA256، ونحدد ARM64 أو x86 ومحمّل Linux والمكتبات المطلوبة. الفحص قراءة فقط؛ حتى ملف ELF صحيح لا يعني إمكانية تشغيل Wine أو Box64.", 14, MUTED, false));
        inventory.addView(button("تدقيق مكونات المحرك المحفوظة", true, v -> runStagedInventory()));
        stagedAuditView = text("لم يتم تدقيق الملفات المخزونة بعد.", 12, WHITE, false);
        stagedAuditView.setTextDirection(View.TEXT_DIRECTION_LTR);
        stagedAuditView.setGravity(Gravity.LEFT);
        stagedAuditView.setTextIsSelectable(true);
        stagedAuditView.setTypeface(Typeface.MONOSPACE);
        stagedAuditView.setPadding(dp(10), dp(10), dp(10), dp(10));
        stagedAuditView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        inventory.addView(stagedAuditView);

        LinearLayout processExec = card("11  •  اختبار تشغيل ملف ARM64 مستقل (V1.1)");
        processExec.addView(text("نبدأ عملية مستقلة فعلية من ملف Android ELF أصلي مضمّن داخل APK ونقرأ النتيجة ورمز الخروج. هذا يختبر مسار تشغيل عملية محرك مستقبلية، وليس Box64 أو Wine أو تشغيل EXE.", 14, MUTED, false));
        processExec.addView(button("تشغيل الملف التنفيذي ARM64", true, v -> runPackagedNativeProcess()));
        processExecStatusView = text("لم يتم تشغيل العملية المستقلة بعد.", 12, WHITE, false);
        processExecStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        processExecStatusView.setGravity(Gravity.LEFT);
        processExecStatusView.setTextIsSelectable(true);
        processExecStatusView.setTypeface(Typeface.MONOSPACE);
        processExecStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        processExecStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        processExec.addView(processExecStatusView);

        LinearLayout signingNote = card("12  •  تحديثات التطبيق (V1.2)");
        signingNote.addView(text("[DEV SIGNING] يستخدم APK التجريبي مفتاح تطوير ثابتاً مضمنًا بالمصدر. ابتداءً من V1.2، يمكن التحديث فوق نسخة موقعة بنفس المفتاح إذا زاد versionCode، وبقي applicationId ثابتاً.", 14, WHITE, false));
        signingNote.addView(text("[ONE-TIME] إذا أندرويد رفض تثبيت V1.2 فوق إصدار قديم، انسخ تقاريرك وملفاتك المهمة خارج التطبيق، ثم أزل القديم وثبّت V1.2 مرة واحدة. إزالة التطبيق تمسح بياناته الداخلية. لا يمكن استخراج المفتاح القديم من APK لتوقيع تحديث مطابق.", 13, MUTED, false));
        signingNote.addView(text("[WARNING] هذا المفتاح معروف لكل من يحصل على ملف المصدر: للاختبار الشخصي فقط، وليس للنشر العام أو تحديثات موثوقة أمنياً. Wine وبيئة Linux الشاملة غير مدمجين؛ Box64 تجريبي فقط.", 13, MUTED, false));

        LinearLayout box64experiment = card("13  •  اختبار Box64 الرسمي على أندرويد (V1.3)");
        box64experiment.addView(text("يحاول GitHub بناء Box64 v0.4.4 الأصلي بمعمارية ARM64 وأندرويد، ثم تضمينه في APK عند النجاح. هنا نشغّل --version فقط من ملف داخل APK، ولا نشغّل برامج x86 أو EXE. بناء Box64 وتوافقه غير مضمونين؛ إذا فشل التجميع، يظهر [NOT BUILT].", 14, MUTED, false));
        box64experiment.addView(button("اختبار إصدار Box64 الحقيقي", true, v -> runOfficialBox64Probe()));
        officialBox64StatusView = text("لم يتم تشغيل تجربة Box64 بعد.", 12, WHITE, false);
        officialBox64StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        officialBox64StatusView.setGravity(Gravity.LEFT);
        officialBox64StatusView.setTextIsSelectable(true);
        officialBox64StatusView.setTypeface(Typeface.MONOSPACE);
        officialBox64StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        officialBox64StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        box64experiment.addView(officialBox64StatusView);

        LinearLayout guestExperiment = card("14  •  اختبار برنامج Linux x86-64 (V1.4.1)");
        guestExperiment.addView(text("نستخدم Box64 الأصلي لتجربة ملف ELF صغير من صنع RM11، مُضمّن داخل APK بدون مكتبات glibc، لا نعتمد على تنزيل برامج مجهولة. يفحص حسابات وتعليمات x86-64 واستدعاءات Linux؛ النجاح لا يعني تشغيل Windows EXE أو الألعاب. بناء Box64 وتشغيل هذا الملف قد يفشلان على أندرويد.", 14, MUTED, false));
        guestExperiment.addView(button("تشغيل اختبار x86-64 بواسطة Box64", true, v -> runBox64GuestSmokeTest()));
        box64GuestStatusView = text("لم يتم تشغيل اختبار x86-64 بعد.", 12, WHITE, false);
        box64GuestStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64GuestStatusView.setGravity(Gravity.LEFT);
        box64GuestStatusView.setTextIsSelectable(true);
        box64GuestStatusView.setTypeface(Typeface.MONOSPACE);
        box64GuestStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64GuestStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        guestExperiment.addView(box64GuestStatusView);

        LinearLayout dynamicGuest = card("15  •  اختبار مكتبات Linux الديناميكية (V1.5)");
        dynamicGuest.addView(text("ملف x86-64 تجريبي من صنع RM11 يعتمد على libc.so.6 ومحمّل ld-linux. يفحص التطبيق اعتمادات ELF ثم يحاول تشغيله بواسطة Box64. إذا ظهرت رسالة نقص مكتبات، نعرضها كما هي. لا تتضمن النسخة glibc أو Wine أو بيئة Linux متكاملة.", 14, MUTED, false));
        dynamicGuest.addView(button("اختبار برنامج x86-64 الديناميكي", true, v -> runBox64DynamicGlibcTest()));
        box64DynamicStatusView = text("لم يُشغّل اختبار المكتبات الديناميكية بعد.", 12, WHITE, false);
        box64DynamicStatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64DynamicStatusView.setGravity(Gravity.LEFT);
        box64DynamicStatusView.setTextIsSelectable(true);
        box64DynamicStatusView.setTypeface(Typeface.MONOSPACE);
        box64DynamicStatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64DynamicStatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        dynamicGuest.addView(box64DynamicStatusView);

        LinearLayout abDiagnostic = card("16  •  تشخيص Dynarec والمكتبات (V1.6)");
        abDiagnostic.addView(text("يشغّل نفس ملف Linux x86-64 التجريبي الديناميكي مرتين بواسطة Box64: مع Dynarec ثم بدونه. يقارن رمز الخروج وظهور علامة النجاح، ويختصر رسائل الانهيار. لا يثبت دعم Wine أو EXE أو الألعاب.", 14, MUTED, false));
        abDiagnostic.addView(button("مقارنة تشغيل Dynarec ON / OFF", true, v -> runBox64V16Diagnostic()));
        box64V16StatusView = text("لم يبدأ تشخيص V1.6 بعد.", 12, WHITE, false);
        box64V16StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64V16StatusView.setGravity(Gravity.LEFT);
        box64V16StatusView.setTextIsSelectable(true);
        box64V16StatusView.setTypeface(Typeface.MONOSPACE);
        box64V16StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64V16StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        abDiagnostic.addView(box64V16StatusView);

        LinearLayout libcStartup = card("17  •  عزل مشكلة __libc_start_main (V1.7)");
        libcStartup.addView(text("نقارن البرنامج الديناميكي السابق ببرنامج x86-64 ديناميكي جديد يستدعي libc write@PLT بدون glibc CRT. كلاهما يستخدم Box64 بنفس وضع التشغيل. نجاح الاختبار الثاني لا يصلح الرمز المفقود بالبرامج الأخرى ولا يعني تشغيل Wine.", 14, MUTED, false));
        libcStartup.addView(button("اختبار libc write بدون CRT", true, v -> runBox64V17Trial()));
        box64V17StatusView = text("لم يبدأ اختبار V1.7 بعد.", 12, WHITE, false);
        box64V17StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64V17StatusView.setGravity(Gravity.LEFT);
        box64V17StatusView.setTextIsSelectable(true);
        box64V17StatusView.setTypeface(Typeface.MONOSPACE);
        box64V17StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64V17StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        libcStartup.addView(box64V17StatusView);

        LinearLayout v18 = card("18  •  إصلاح بدء glibc الحقيقي (V1.8)");
        v18.addView(text("جرّبنا تعديل شفرة Box64 الرسمية أثناء بناء أندرويد حتى يحتفظ بمدخل Bionic ويضم أيضاً دالة بدء glibc. نختبر نفس البرنامج الديناميكي القديم الذي فشل، ومعه برنامج libc بدون CRT كمقارنة. نجاح البناء لا يعني نجاح تشغيل البرنامج أو دعم Wine.", 14, MUTED, false));
        v18.addView(button("اختبار __libc_start_main بعد الإصلاح", true, v -> runBox64V18Trial()));
        box64V18StatusView = text("لم يبدأ اختبار V1.8 بعد.", 12, WHITE, false);
        box64V18StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64V18StatusView.setGravity(Gravity.LEFT);
        box64V18StatusView.setTextIsSelectable(true);
        box64V18StatusView.setTypeface(Typeface.MONOSPACE);
        box64V18StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64V18StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        v18.addView(box64V18StatusView);

        LinearLayout v19 = card("19  •  توافق مكتبات Linux x86-64 (V1.9)");
        v19.addView(text("أربع اختبارات فعلية منفصلة عبر Box64: malloc/free وإدارة الذاكرة، قراءة وكتابة ملف مؤقت داخل التطبيق، pthread، و dlopen/dlsym لـ libm. كل فحص يعطي PASS أو FAIL مستقل. لا يتطلب صلاحيات واسعة أو تحميل برامج خارجية؛ النجاح لا يعني تشغيل Wine أو ألعاب ويندوز.", 14, MUTED, false));
        box64V19Button = button("تشغيل اختبارات التوافق الأربعة", true, v -> runBox64V19Probes());
        v19.addView(box64V19Button);
        box64V19StatusView = text("لم يتم تشغيل اختبارات V1.9 بعد.", 12, WHITE, false);
        box64V19StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        box64V19StatusView.setGravity(Gravity.LEFT);
        box64V19StatusView.setTextIsSelectable(true);
        box64V19StatusView.setTypeface(Typeface.MONOSPACE);
        box64V19StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        box64V19StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        v19.addView(box64V19StatusView);

        LinearLayout wine = card("20  •  تشغيل Wine الحقيقي عبر Box64 — تجريبي (V2.0)");
        wine.addView(text("نحاول تشغيل ملف Wine x86-64 الأصلي من حزمة Linux موثوقة بواسطة Box64 ونقرأ فقط --version. بدون ملفات DLL أو wineserver أو بيئة Linux كاملة لا يوجد ضمان للنجاح. لا نشغّل ملفات EXE أو ألعاباً في هذه التجربة.", 14, MUTED, false));
        wineV20Button = button("اختبار إصدار Wine الحقيقي", true, v -> runWineV20Version());
        wine.addView(wineV20Button);
        wineV20StatusView = text("لم يتم اختبار Wine بعد.", 12, WHITE, false);
        wineV20StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        wineV20StatusView.setGravity(Gravity.LEFT);
        wineV20StatusView.setTextIsSelectable(true);
        wineV20StatusView.setTypeface(Typeface.MONOSPACE);
        wineV20StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        wineV20StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        wine.addView(wineV20StatusView);

        LinearLayout wine21 = card("21  •  اختبار Wine مع جسر glibc (V2.1.4)");
        wine21.addView(text("نحاول تضمين Wine64 وملفات ntdll.so / ntdll.dll و wineserver64 من حزمتين متطابقتين. نفحص البصمات ونحافظ على مسارات التثبيت الأصلية، ثم نجرب wine64 --version فقط عبر Box64. ظهور PASS لا يعني تشغيل EXE أو الألعاب.", 14, MUTED, false));
        wineV21Button = button("اختبار Wine و ntdll.so", true, v -> runWineV21Version());
        wine21.addView(wineV21Button);
        wineV21StatusView = text("لم يتم تشغيل اختبار Wine V2.1 بعد.", 12, WHITE, false);
        wineV21StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        wineV21StatusView.setGravity(Gravity.LEFT);
        wineV21StatusView.setTextIsSelectable(true);
        wineV21StatusView.setTypeface(Typeface.MONOSPACE);
        wineV21StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        wineV21StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        wine21.addView(wineV21StatusView);

        LinearLayout wine22 = card("22  •  تهيئة Wine ثم اختبار Windows EXE (V2.3.5)");
        wine22.addView(text("نشغّل EXE أصلي x86-64 صنعناه للمشروع، ويستدعي CreateFileA / WriteFile من Windows API عبر Wine وBox64، لكتابة علامة نجاح ضمن مجلد التطبيق الخاص. نفحص البصمة وعلامة النجاح ورمز الخروج، ونضمّن ملفات اللغة ونختبر تصحيح ربط ترميز CODESET في Box64، مع إبقاء حماية المؤشرات في الاختبار العادي. أضفنا اختبار عزل مستقل يخفض حماية heap داخل عملية Box64 فقط عند طلبك؛ هذا للتشخيص وليس علاجاً للخلل. لا نشغّل ملفات خارجية أو ألعاباً أو رسومات؛ قد تظهر تبعيات Wine ناقصة.", 14, MUTED, false));
        wine22.addView(text("V2.3.5: تهيئة Wine داخل مساحة جديدة، مع Dynarec في الاختبار العادي وتسجيل أقل إزعاجاً، ومهلة إقلاع 120 ثانية. ابدأ بالزر الأول؛ لا تختبر EXE إلا عند ظهور [BOOT READY].", 13, MUTED, false));
        wineV233BootButton = button("1 — تهيئة Wine V2.3.8", true, v -> runWineV233Boot());
        wine22.addView(wineV233BootButton);
        wineV22Button = button("2 — اختبار أول Windows EXE", true, v -> runWineV22Exe());
        wine22.addView(wineV22Button);
        wine22.addView(text("اختياري: اختبار عزل heap يعطّل فحص وسم مؤشرات الذاكرة مؤقتاً داخل عملية Box64 المنفصلة فقط؛ يخفض الحماية ولا يصلح المؤشرات الخاطئة.", 12, MUTED, false));
        wineV22HeapButton = button("تشخيص heap المؤقت (أقل حماية)", false, v -> runWineV22HeapDiagnostic());
        wine22.addView(wineV22HeapButton);
        wine22.addView(text("اختبار سابق اختياري: نختبر تتبع تخصيص Box64 بإعداد BOX64_MALLOC_HACK=2 في عملية منفصلة، مع إبقاء حماية مؤشرات أندرويد مفعّلة. اختبار تجريبي فقط؛ لا يشغّل ألعاباً.", 12, MUTED, false));
        wineV22MallocButton = button("تشخيص malloc/free (حماية كاملة)", true, v -> runWineV22MallocDiagnostic());
        wine22.addView(wineV22MallocButton);
        wineV22StatusView = text("لم يتم تنفيذ اختبار Windows EXE بعد.", 12, WHITE, false);
        wineV22StatusView.setTextDirection(View.TEXT_DIRECTION_LTR);
        wineV22StatusView.setGravity(Gravity.LEFT);
        wineV22StatusView.setTextIsSelectable(true);
        wineV22StatusView.setTypeface(Typeface.MONOSPACE);
        wineV22StatusView.setPadding(dp(10), dp(10), dp(10), dp(10));
        wineV22StatusView.setBackground(shape(Color.rgb(11, 18, 29), 10));
        wine22.addView(wineV22StatusView);

        LinearLayout launchers = card("23  •  مركز المشغّلات الرسمية");
        launchers.addView(text("نفتح مواقع الشركات الأصلية فقط، ثم نربط ملف التثبيت الذي اخترته. لن ننسخ المشغّلات أو نطلب كلمات المرور.", 14, MUTED, false));
        for (int i = 0; i < LauncherCatalog.ALL.length; ++i) {
            LauncherCatalog.Launcher item = LauncherCatalog.ALL[i];
            LinearLayout itemBox = column();
            itemBox.setPadding(dp(12), dp(12), dp(12), dp(12));
            itemBox.setBackground(shape(Color.rgb(25, 38, 55), 12));
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
            params.topMargin = dp(10);
            launchers.addView(itemBox, params);
            itemBox.addView(text(item.name, 17, WHITE, true));
            itemBox.addView(text(item.description, 13, MUTED, false));
            TextView linked = text(linkedInstallerStatus(item.id), 12, MINT, false);
            installerStatusViews.put(item.id, linked);
            itemBox.addView(linked);
            itemBox.addView(button("زيارة الموقع الرسمي", false, v -> openOfficial(item.officialUrl)));
            final int index = i;
            itemBox.addView(button("ربط ملف تثبيت EXE / MSI", false, v -> chooseInstaller(index)));
        }

        LinearLayout online = card("24  •  توافق الأونلاين");
        online.addView(text("المشغّل الرسمي ليس تصريحاً لتشغيل لعبة محمية. صلاحية اللعب يحددها ناشر اللعبة ونظام مكافحة الغش.", 14, MUTED, false));
        online.addView(text("• The Crew Motorfest: مشغّل Ubisoft مطلوب؛ التوافق على أندرويد غير مثبت.", 13, WHITE, false));
        online.addView(text("• PUBG PC: لا يوجد إثبات توافق رسمي على محاكينا.", 13, WHITE, false));
        online.addView(text("• Battlefield 6: Secure Boot وEA Javelin عائق حقيقي أمام طبقات Wine.", 13, WHITE, false));
        online.addView(text("• GTA Online: روكستار لا تدعم BattlEye على Steam Deck؛ لا نعد بالدعم هنا.", 13, WHITE, false));

        LinearLayout runtime = card("25  •  حالة محرك الألعاب");
        runtime.addView(text(RuntimeGateway.currentStatusArabic(), 14, MUTED, false));
        runtime.addView(text("خطة الدمج: Wine → Box64 → Vulkan/DXVK → إدخال وصوت → تشغيل برامج اختبار → المشغّلات.", 13, WHITE, false));
        runtime.addView(text("RM11 WinCore مشروع مستقل؛ غير تابع لـ Valve أو Ubisoft أو EA أو Rockstar.", 12, MUTED, false));
    }

    private void runWineV233Boot() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV22StatusView.setText("[STOP] اختبار REDMAGIC NX809J فقط.");
            return;
        }
        wineV233BootButton.setEnabled(false);
        wineV22Button.setEnabled(false);
        wineV22HeapButton.setEnabled(false);
        wineV22MallocButton.setEnabled(false);
        wineV22StatusView.setText("جارٍ اختبار إقلاع Wine عبر Box64 مع Dynarec ومهلة 120 ثانية. لن نشغّل EXE بهذا الاختبار...");
        new Thread(() -> {
            final String result = WineFirstExeV22.runBootstrap(getApplicationContext());
            runOnUiThread(() -> {
                wineV22StatusView.setText(result);
                wineV233BootButton.setEnabled(true);
                wineV22Button.setEnabled(true);
                wineV22HeapButton.setEnabled(true);
                wineV22MallocButton.setEnabled(true);
            });
        }, "rm11-v235-wineboot-init").start();
    }

    private void runWineV22Exe() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV22StatusView.setText("[STOP] اختبار REDMAGIC NX809J فقط.");
            return;
        }
        wineV233BootButton.setEnabled(false);
        wineV22Button.setEnabled(false);
        wineV22HeapButton.setEnabled(false);
        wineV22MallocButton.setEnabled(false);
        wineV22StatusView.setText("جارٍ تشغيل ملف Windows EXE الأصلي عبر Wine + Box64 (مهلة 55 ثانية)...");
        new Thread(() -> {
            final String result = WineFirstExeV22.run(getApplicationContext());
            runOnUiThread(() -> {
                wineV22StatusView.setText(result);
                wineV233BootButton.setEnabled(true);
                wineV22Button.setEnabled(true);
                wineV22HeapButton.setEnabled(true);
                wineV22MallocButton.setEnabled(true);
            });
        }, "rm11-v22-first-win64-exe").start();
    }

    private void runWineV22HeapDiagnostic() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV22StatusView.setText("[STOP] اختبار REDMAGIC NX809J فقط.");
            return;
        }
        wineV233BootButton.setEnabled(false);
        wineV22HeapButton.setEnabled(false);
        wineV22Button.setEnabled(false);
        wineV22MallocButton.setEnabled(false);
        wineV22StatusView.setText("جارٍ اختبار heap داخل عملية Box64 منفصلة (مهلة 55 ثانية). لا يطبق على الجهاز بالكامل...");
        new Thread(() -> {
            final String result = WineFirstExeV22.runHeapDiagnostic(getApplicationContext());
            runOnUiThread(() -> {
                wineV22StatusView.setText(result);
                wineV233BootButton.setEnabled(true);
                wineV22HeapButton.setEnabled(true);
                wineV22Button.setEnabled(true);
                wineV22MallocButton.setEnabled(true);
            });
        }, "rm11-v224-isolated-heap-test").start();
    }

    private void runWineV22MallocDiagnostic() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV22StatusView.setText("[STOP] اختبار REDMAGIC NX809J فقط.");
            return;
        }
        wineV233BootButton.setEnabled(false);
        wineV22Button.setEnabled(false);
        wineV22HeapButton.setEnabled(false);
        wineV22MallocButton.setEnabled(false);
        wineV22StatusView.setText("جارٍ مقارنة malloc/free باستخدام BOX64_MALLOC_HACK=2 وحماية أندرويد مفعّلة...");
        new Thread(() -> {
            final String result = WineFirstExeV22.runMallocTrackingDiagnostic(getApplicationContext());
            runOnUiThread(() -> {
                wineV22StatusView.setText(result);
                wineV233BootButton.setEnabled(true);
                wineV22Button.setEnabled(true);
                wineV22HeapButton.setEnabled(true);
                wineV22MallocButton.setEnabled(true);
            });
        }, "rm11-v225-malloc-tracking-test").start();
    }

    private void runWineV21Version() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV21StatusView.setText("[STOP] اختبار REDMAGIC NX809J فقط.");
            return;
        }
        wineV21Button.setEnabled(false);
        wineV21StatusView.setText("جارٍ اختبار Wine + ntdll.so الفعلي عبر Box64 (مهلة 18 ثانية)...");
        new Thread(() -> {
            final String result = WineRuntimeV21.run(getApplicationContext());
            runOnUiThread(() -> {
                wineV21StatusView.setText(result);
                wineV21Button.setEnabled(true);
            });
        }, "rm11-v21-wine-ntdll").start();
    }

    private void runWineV20Version() {
        if (!RuntimeBootstrap.correctDevice()) {
            wineV20StatusView.setText("[STOP] مخصص لهاتف REDMAGIC NX809J.");
            return;
        }
        wineV20Button.setEnabled(false);
        wineV20StatusView.setText("جارٍ محاولة تشغيل إصدار Wine الحقيقي بواسطة Box64. مهلة 12 ثانية...");
        new Thread(() -> {
            final String result = WineLoaderV20.run(getApplicationContext());
            runOnUiThread(() -> {
                wineV20StatusView.setText(result);
                wineV20Button.setEnabled(true);
            });
        }, "rm11-v20-wine-version").start();
    }

    private void runPackagedNativeProcess() {
        if (!RuntimeBootstrap.correctDevice()) {
            processExecStatusView.setText("[STOP] اختبار V1.1 مخصص لهاتف REDMAGIC NX809J.");
            return;
        }
        processExecStatusView.setText("جاري تشغيل ملف ARM64 الأصلي المستقل من داخل APK...");
        new Thread(() -> {
            final String result = PackagedNativeProcess.runSelfTest(getApplicationContext());
            runOnUiThread(() -> processExecStatusView.setText(result));
        }, "rm11-packaged-exec-probe").start();
    }

    private void runOfficialBox64Probe() {
        if (!RuntimeBootstrap.correctDevice()) {
            officialBox64StatusView.setText("[STOP] هذا الاختبار مخصص لهاتف REDMAGIC NX809J.");
            return;
        }
        officialBox64StatusView.setText("جاري فحص وجود Box64 وتشغيل --version فقط...");
        new Thread(() -> {
            final String info = OfficialBox64Probe.inspect(getApplicationContext());
            runOnUiThread(() -> officialBox64StatusView.setText(info));
        }, "rm11-box64-version-probe").start();
    }

    private void runBox64GuestSmokeTest() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64GuestStatusView.setText("[STOP] الاختبار مخصص لهاتف REDMAGIC NX809J.");
            return;
        }
        box64GuestStatusView.setText("جاري محاولة تنفيذ برنامج Linux x86-64 عبر Box64 الحقيقي…");
        new Thread(() -> {
            final String result = Box64GuestSmokeTest.run(getApplicationContext());
            runOnUiThread(() -> box64GuestStatusView.setText(result));
        }, "rm11-box64-x86-guest").start();
    }

    private void runBox64V19Probes() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64V19StatusView.setText("[STOP] التجربة مخصصة لهاتف REDMAGIC NX809J.");
            return;
        }
        box64V19Button.setEnabled(false);
        box64V19StatusView.setText("جاري اختبار 4 عمليات منفصلة عبر Box64... قد يستغرق حتى 45 ثانية.");
        new Thread(() -> {
            final String result = Box64AbiCompatibilityV19.run(getApplicationContext());
            runOnUiThread(() -> {
                box64V19StatusView.setText(result);
                box64V19Button.setEnabled(true);
            });
        }, "rm11-v19-abi-probes").start();
    }

    private void runBox64V16Diagnostic() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64V16StatusView.setText("[STOP] مخصص لجهاز REDMAGIC NX809J.");
            return;
        }
        box64V16StatusView.setText("جارٍ اختبار Dynarec ON ثم OFF، قد يستغرق حتى 30 ثانية...");
        new Thread(() -> {
            final String result = Box64DynarecDiagnostic.run(getApplicationContext());
            runOnUiThread(() -> box64V16StatusView.setText(result));
        }, "rm11-v16-dynarec").start();
    }

    private void runBox64V17Trial() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64V17StatusView.setText("[STOP] مخصص لجهاز REDMAGIC NX809J.");
            return;
        }
        box64V17StatusView.setText("جارٍ اختبار ملفين ديناميكيين بنفس إعدادات Box64؛ قد يستغرق 30 ثانية...");
        new Thread(() -> {
            final String result = Box64LibcStartupTrial.run(getApplicationContext());
            runOnUiThread(() -> box64V17StatusView.setText(result));
        }, "rm11-v17-startup-trial").start();
    }

    private void runBox64V18Trial() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64V18StatusView.setText("[STOP] مخصص لهاتف REDMAGIC NX809J.");
            return;
        }
        box64V18StatusView.setText("جارٍ فحص تطبيق إصلاح Box64 واختبار بدء glibc الأصلي (حوالي 30 ثانية)...");
        new Thread(() -> {
            final String result = Box64LibcStartupTrial.runV18Regression(getApplicationContext());
            runOnUiThread(() -> box64V18StatusView.setText(result));
        }, "rm11-v18-glibc-crt-regression").start();
    }

    private void runBox64DynamicGlibcTest() {
        if (!RuntimeBootstrap.correctDevice()) {
            box64DynamicStatusView.setText("[STOP] التجربة مخصصة لهاتف REDMAGIC NX809J.");
            return;
        }
        box64DynamicStatusView.setText("جاري تحليل برنامج x86-64 واعتمادات glibc ومحاولة تشغيله عبر Box64…");
        new Thread(() -> {
            final String result = Box64DynamicGlibcTest.run(getApplicationContext());
            runOnUiThread(() -> box64DynamicStatusView.setText(result));
        }, "rm11-box64-glibc-guest").start();
    }

    private void runScan() {
        scanButton.setEnabled(false);
        scanButton.setText("جاري فحص Vulkan ومواصفات الجهاز…");
        reportView.setText("جاري الفحص محلياً، بدون إرسال البيانات إلى أي خادم.");
        new Thread(() -> {
            String result;
            try { result = DeviceProbe.inspect(getApplicationContext()); }
            catch (Throwable t) { result = "فشل الفحص: " + t; }
            final String finalResult = result;
            runOnUiThread(() -> {
                report = finalResult;
                reportView.setText(report);
                scanButton.setText("إعادة فحص الهاتف");
                scanButton.setEnabled(true);
            });
        }, "rm11-device-probe").start();
    }

    private void runPreflight() {
        preflightButton.setEnabled(false);
        preflightButton.setText("جاري فحص جاهزية المحرك…");
        preflightView.setText("جاري فحص العتاد محلياً. لا يتم تشغيل أي ملف EXE.");
        new Thread(() -> {
            String result;
            try { result = RuntimeReadiness.inspect(getApplicationContext()); }
            catch (Throwable t) { result = "Preflight error: " + t.getMessage(); }
            final String finalResult = result;
            runOnUiThread(() -> {
                preflightView.setText(finalResult);
                preflightButton.setText("إعادة فحص جاهزية المحرك");
                preflightButton.setEnabled(true);
            });
        }, "rm11-runtime-preflight").start();
    }

    private void runStagedInventory() {
        stagedAuditView.setText("جاري تدقيق الملفات المحفوظة محلياً دون تشغيلها...");
        new Thread(() -> {
            String info = StagedEngineInventory.inspect(getApplicationContext());
            runOnUiThread(() -> stagedAuditView.setText(info));
        }, "rm11-staged-runtime-inventory").start();
    }

    private void runBootstrap(boolean subprocess) {
        runtimeV03View.setText("جاري الاختبار المحلي…");
        new Thread(() -> {
            String info = subprocess ? RuntimeBootstrap.testSubprocess(getApplicationContext()) :
                RuntimeBootstrap.init(getApplicationContext());
            runOnUiThread(() -> runtimeV03View.setText(info));
        }, "rm11-runtime-bootstrap").start();
    }

    private void chooseBundleToStage() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("application/zip");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(picker, STAGE_ENGINE_BUNDLE); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void chooseElfRuntime() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(picker, ELF_RUNTIME_PICK); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void chooseGameForProfile() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(picker, GAME_PROFILE_PICK); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void exportGameProfile() {
        if (gameProfile.startsWith("لم يتم")) {
            Toast.makeText(this, "اختار ملف EXE وحلّله أولاً.", Toast.LENGTH_LONG).show();
            return;
        }
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("text/plain");
        save.putExtra(Intent.EXTRA_TITLE, "RM11-Smart-Balance-Report.txt");
        try { startActivityForResult(save, GAME_PROFILE_EXPORT); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تصدير الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void chooseEngineBundle() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("application/zip");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(picker, VERIFY_ENGINE_BUNDLE); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void choosePe() {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(picker, INSPECT_PE); }
        catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private void openOfficial(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "ماكو متصفح مثبت لفتح الرابط.", Toast.LENGTH_LONG).show();
        }
    }

    private void chooseInstaller(int index) {
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            startActivityForResult(picker, IMPORT_BASE + index);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "تطبيق اختيار الملفات غير متوفر.", Toast.LENGTH_LONG).show();
        }
    }

    private String displayName(Uri uri) {
        String name = null;
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) name = c.getString(0);
        } catch (Exception ignored) { }
        return name != null ? name : uri.getLastPathSegment();
    }

    private SharedPreferences preferences() {
        return getSharedPreferences("launcher-installer-uris", MODE_PRIVATE);
    }

    private String linkedInstallerStatus(String id) {
        String name = preferences().getString("name." + id, null);
        return name == null ? "الحالة: لم يتم ربط ملف تثبيت بعد" : "ملف مرتبط: " + name + "  •  غير مثبّت";
    }

    private void exportReport() {
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("text/plain");
        save.putExtra(Intent.EXTRA_TITLE, "RM11-WinCore-Device-Report.txt");
        try { startActivityForResult(save, REPORT_EXPORT); }
        catch (ActivityNotFoundException e) { Toast.makeText(this, "تصدير الملفات غير متوفر.", Toast.LENGTH_LONG).show(); }
    }

    @Override @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (requestCode == STAGE_ENGINE_BUNDLE) {
            new AlertDialog.Builder(this)
                .setTitle("حفظ مكونات فقط — لا تشغيل")
                .setMessage("سيتحقق التطبيق من الملف ويحفظ محتوياته داخل مساحة التطبيق كبيانات غير قابلة للتنفيذ. هذا لا يثبت Wine/Box64 ولا يتيح تشغيل EXE. أكمل فقط مع حزمة من مصدر موثوق.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("فحص وحفظ", (dialog, choice) -> {
                    stagedBundleStatusView.setText("جاري فحص الحزمة وحفظ البيانات بشكل آمن...");
                    new Thread(() -> {
                        String result = EngineBundleStager.stage(getApplicationContext(), uri);
                        runOnUiThread(() -> stagedBundleStatusView.setText(result));
                    }, "rm11-inert-engine-stager").start();
                }).show();
            return;
        }
        if (requestCode == ELF_RUNTIME_PICK) {
            String chosenName = displayName(uri);
            elfRuntimeStatusView.setText("جاري فحص ترويسة ELF ومكتباتها محلياً بدون تنفيذ...");
            new Thread(() -> {
                String info;
                try (java.io.InputStream in = getContentResolver().openInputStream(uri)) {
                    ElfRuntimeInspector.Report elf = ElfRuntimeInspector.analyze(in);
                    info = ElfRuntimeInspector.explain(elf, chosenName);
                } catch (Exception ex) {
                    info = "[FAIL] لم نتمكن من قراءة ملف ELF: " + ex.getMessage();
                }
                final String result = info;
                runOnUiThread(() -> elfRuntimeStatusView.setText(result));
            }, "rm11-elf-runtime-audit").start();
            return;
        }
        if (requestCode == GAME_PROFILE_PICK) {
            String chosenName = displayName(uri);
            if (chosenName == null || !chosenName.toLowerCase(Locale.ROOT).endsWith(".exe")) {
                gameProfileView.setText("[FAIL] اختار ملف Windows EXE فقط، مو APK أو ZIP.");
                return;
            }
            gameProfileView.setText("جاري تحليل ملف EXE محلياً، بدون تثبيت أو تشغيل...");
            new Thread(() -> {
                String info;
                try (java.io.InputStream in = getContentResolver().openInputStream(uri)) {
                    WindowsExecutableAnalyzer.Result pe = WindowsExecutableAnalyzer.analyze(in, chosenName);
                    info = SmartGameProfile.recommend(pe);
                } catch (Exception ex) {
                    info = "[FAIL] فشل تحليل EXE: " + ex.getClass().getSimpleName() + ": " + ex.getMessage();
                }
                final String result = info;
                runOnUiThread(() -> {
                    gameProfile = result;
                    gameProfileView.setText(result);
                });
            }, "rm11-smart-balance-preview").start();
            return;
        }
        if (requestCode == GAME_PROFILE_EXPORT) {
            try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                if (out == null) throw new IllegalStateException("No output stream");
                out.write(gameProfile.getBytes(StandardCharsets.UTF_8));
                Toast.makeText(this, "تم حفظ تقرير التوازن المبدئي.", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "تعذر حفظ التقرير: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
            return;
        }
        if (requestCode == VERIFY_ENGINE_BUNDLE) {
            engineBundleStatusView.setText("جاري تدقيق الحزمة بدون تثبيت أو تشغيل...");
            new Thread(() -> {
                String info = EngineBundleVerifier.verify(getContentResolver(), uri);
                runOnUiThread(() -> engineBundleStatusView.setText(info));
            }, "rm11-bundle-audit").start();
            return;
        }
        if (requestCode == INSPECT_PE) {
            runtimeV03View.setText("جاري فحص ترويسة الملف، دون تشغيله…");
            new Thread(() -> {
                String info = PeInspector.inspect(getContentResolver(), uri);
                runOnUiThread(() -> runtimeV03View.setText(info));
            }, "rm11-pe-inspector").start();
            return;
        }
        if (requestCode == REPORT_EXPORT) {
            try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                if (out == null) throw new IllegalStateException("No output stream");
                out.write(report.getBytes(StandardCharsets.UTF_8));
                Toast.makeText(this, "تم حفظ تقرير الفحص.", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "تعذر حفظ التقرير: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
            return;
        }
        int index = requestCode - IMPORT_BASE;
        if (index < 0 || index >= LauncherCatalog.ALL.length) return;
        String name = displayName(uri);
        if (name == null) name = "unknown";
        String lowerName = name.toLowerCase(Locale.ROOT);
        if (!(lowerName.endsWith(".exe") || lowerName.endsWith(".msi"))) {
            new AlertDialog.Builder(this).setTitle("ملف غير مناسب")
                .setMessage("اختار ملف تثبيت ويندوز أصلي بامتداد EXE أو MSI.")
                .setPositiveButton("حسناً", null).show();
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException exception) {
            Toast.makeText(this, "لم يتم تثبيت إذن الملف؛ قد تحتاج إلى إعادة اختياره لاحقاً.", Toast.LENGTH_LONG).show();
        }
        String id = LauncherCatalog.ALL[index].id;
        preferences().edit().putString("uri." + id, uri.toString()).putString("name." + id, name).apply();
        TextView status = installerStatusViews.get(id);
        if (status != null) status.setText(linkedInstallerStatus(id));
        new AlertDialog.Builder(this)
            .setTitle("تم ربط الملف")
            .setMessage("حُفظ رابط ملف «" + name + "» على هاتفك. لم يتم تثبيته أو تشغيله لأن محرك Wine غير مدمج في النسخة الحالية.")
            .setPositiveButton("مفهوم", null).show();
    }
}
