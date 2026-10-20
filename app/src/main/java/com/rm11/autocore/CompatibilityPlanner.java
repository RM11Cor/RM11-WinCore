package com.rm11.autocore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Conservative compatibility PRE-FLIGHT planner.
 *
 * Input: ONLY evidence already observed locally by the read-only detector.
 * Output: roles of components to investigate, not guessed binary versions or
 * a claim that a game will launch. No game-specific title registry.
 *
 * This does NOT install/execute FEX, Wine, Proton, DXVK, VKD3D or Turnip.
 */
public final class CompatibilityPlanner {
    private CompatibilityPlanner() { }

    public static final class Component {
        public final String id;
        public final String purpose;
        public final String decision;
        public final String reason;
        Component(String id, String purpose, String decision, String reason) {
            this.id = id;
            this.purpose = purpose;
            this.decision = decision;
            this.reason = reason;
        }
    }

    public static final class Plan {
        public final String state;
        public final String launchReadiness;
        public final String requirements;
        public final String protection;
        public final String store;
        public final String blockers;
        public final List<Component> components;
        public final List<String> evidence;
        Plan(String state, String launchReadiness, String requirements, String protection,
             String store, String blockers, List<Component> components, List<String> evidence) {
            this.state = state;
            this.launchReadiness = launchReadiness;
            this.requirements = requirements;
            this.protection = protection;
            this.store = store;
            this.blockers = blockers;
            this.components = Collections.unmodifiableList(new ArrayList<>(components));
            this.evidence = Collections.unmodifiableList(new ArrayList<>(evidence));
        }
    }

    public static Plan build(GameDetector.Detection detected, GameManifestReader.Result metadata,
                             List<GameDetector.Entry> files) {
        List<Component> components = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        if (files == null) files = Collections.emptyList();
        boolean gameExe = detected != null && detected.exe != null && !detected.exe.isEmpty();
        String architecture = detected == null ? "" : detected.architecture.toLowerCase(Locale.ROOT);
        String graphics = detected == null ? "" : detected.graphics.toLowerCase(Locale.ROOT);

        String cpuDecision;
        if (!gameExe) cpuDecision = "غير قابل للتحديد";
        else if (architecture.contains("x86-64") || architecture.contains("x64") || architecture.contains("x86-32")
                || architecture.equals("x86") || architecture.contains("i386")) {
            cpuDecision = "طبقة ترجمة مطلوبة مبدئياً";
            evidence.add("معمارية EXE تشير إلى x86 على هاتف ARM64؛ يلزم فحص محرك ترجمة مناسب");
        } else if (architecture.contains("arm64")) cpuDecision = "قد لا يتطلب ترجمة x86";
        else cpuDecision = "بنية EXE غير محسومة؛ لا تختَر مترجماً تلقائياً";
        components.add(new Component("CPU_TRANSLATOR", "FEX أو بديل متوافق مع بيئة ARM64",
                cpuDecision, "اختيار إصدار FEX يتطلب اختباراً فعلياً على الجهاز؛ ليس مبنياً على اسم اللعبة"));
        components.add(new Component("WINDOWS_LAYER", "Wine/Proton: واجهات Windows المطلوبة للبرنامج",
                gameExe ? "يلزم محرك تشغيل Windows" : "معلّق لحين تحديد EXE",
                "لا توجد بيئة Wine/Proton مدمجة حالياً، ولا إصدار موثوق محدد تلقائياً"));

        // The detector's graphics field comes from directly imported PE DLLs (if present).
        // An absent PE import does not mean the game lacks that API: engines can dlopen DLLs.
        boolean dx12 = graphics.contains("directx 12");
        boolean dx11or9 = graphics.contains("directx 11") || graphics.contains("directx 10")
                || graphics.contains("directx 9") || graphics.contains("directx 8");
        boolean vulkan = graphics.contains("vulkan");
        boolean gl = graphics.contains("opengl");
        String dxvk = dx11or9 ? "مرشح تقني، وليس إعداداً مؤكداً" : "غير محسوم؛ لا تفعّله تلقائياً";
        String vkd3d = dx12 ? "مرشح تقني، وليس إعداداً مؤكداً" : "غير محسوم؛ لا تفعّله تلقائياً";
        components.add(new Component("DXVK", "ترجمة Direct3D 8/9/10/11 إلى Vulkan", dxvk,
                dx11or9 ? "ظهرت قرينة استيراد DirectX أقدم من 12" : "لا يوجد دليل PE مباشر؛ قد تستخدم اللعبة تحميل DLL ديناميكياً"));
        components.add(new Component("VKD3D", "ترجمة Direct3D 12 إلى Vulkan", vkd3d,
                dx12 ? "ظهرت قرينة استيراد D3D12" : "لا يوجد دليل PE مباشر على D3D12"));
        components.add(new Component("GPU_DRIVER", "تعريف Vulkan/Turnip متوافق مع Adreno",
                "يلزم اختبار الجهاز والتعريف", "إصدار Turnip غير مستنتج من الملفات، ولا نضمن دعم الميزات المطلوبة"));
        if (vulkan) evidence.add("قرينة Vulkan مباشرة؛ قد لا تحتاج ترجمة DirectX لهذا المسار");
        if (gl) evidence.add("قرينة OpenGL؛ يلزم فحص طريقة الترجمة الرسومية المناسبة");
        if (dx12 && dx11or9) evidence.add("ظهرت قرائن لأكثر من إصدار DirectX؛ لا نختار المسار من جدول imports وحده");
        if (!dx12 && !dx11or9 && !vulkan && !gl) evidence.add("API الرسومات غير معروف؛ ربما يُحمّل داخل المحرك وقت التشغيل");

        boolean eac = false, battleye = false;
        for (GameDetector.Entry entry : files) {
            if (entry == null) continue;
            String p = entry.path.toLowerCase(Locale.ROOT);
            if (p.contains("easyanticheat") || p.contains("easy anti-cheat") || p.contains("eac_eos")
                    || p.contains("eaclauncher")) eac = true;
            if (p.contains("battleye") || p.contains("beservice") || p.endsWith("/beclient_x64.dll")) battleye = true;
        }
        String protection = eac && battleye ? "رُصدت مؤشرات Easy Anti-Cheat وBattlEye"
                : eac ? "رُصدت مؤشرات Easy Anti-Cheat"
                : battleye ? "رُصدت مؤشرات BattlEye" : "لم تُرصد حماية مدعومة بهذا الفحص؛ لا ينفي وجودها";
        if (eac || battleye) evidence.add("وجود ملفات حماية لا يثبت أن التشغيل عبر Wine/Proton مدعوم أو أن الحماية تعمل");

        String store = detected == null ? "غير معروف" : detected.platform;
        if (metadata != null && !metadata.platform.isEmpty()) store = metadata.platform;
        if (metadata != null && !metadata.steamAppId.isEmpty()) evidence.add("Steam AppID محلي مرشح للبحث الخارجي، لا يثبت ملكية اللعبة أو متطلبات متجرها");
        boolean limited = detected != null && detected.truncated;
        if (limited) evidence.add("الفهرسة محدودة؛ يجب توسيع الفحص قبل توصية عالية الثقة");
        String blockers = !gameExe ? "ملف تشغيل مناسب لم يُحدد"
                : eac || battleye ? "توافق الحماية يحتاج تأكيد دعم المطوّر واختباراً فعلياً"
                : "لم يُختبر محرك Windows على الجهاز بعد";
        String requirements = "Windows/CPU/RAM/VRAM/DirectX الرسمية غير متحققة محلياً؛ تحتاج قاعدة موثقة بمصدرها وإصدارها";
        return new Plan("مسودة تخطيط مبنية على أدلة محلية — غير مختبرة",
                "غير جاهز للتشغيل: محرك Windows غير مدمج بالنسخة الحالية",
                requirements, protection, store, blockers, components, evidence);
    }
}
