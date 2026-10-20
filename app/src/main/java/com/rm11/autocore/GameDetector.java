package com.rm11.autocore;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Generic, read-only game-folder inference. No hardcoded game titles or game-specific mappings. */
public final class GameDetector {
    private GameDetector() { }

    public static final class Entry {
        public final String path;
        public final boolean directory;
        public final long size;
        public final String productName;
        public final String fileDescription;
        public final String productVersion;
        public final String architecture;
        public final List<String> importedDlls;
        public Entry(String path, boolean directory) { this(path, directory, -1, "", "", ""); }
        public Entry(String path, boolean directory, long size) { this(path, directory, size, "", "", ""); }
        public Entry(String path, boolean directory, long size, String productName,
                     String fileDescription, String productVersion) {
            this(path, directory, size, productName, fileDescription, productVersion,
                    "غير محدد", Collections.emptyList());
        }
        public Entry(String path, boolean directory, long size, String productName,
                     String fileDescription, String productVersion,
                     String architecture, List<String> importedDlls) {
            this.path = path == null ? "" : path.replace('\\', '/');
            this.directory = directory;
            this.size = size;
            this.productName = clean(productName);
            this.fileDescription = clean(fileDescription);
            this.productVersion = clean(productVersion);
            this.architecture = clean(architecture);
            this.importedDlls = importedDlls == null ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(importedDlls));
        }
    }

    public static final class Detection {
        public final String title, gameId, exe, graphics, platform, certainty, version, engine, architecture;
        public final List<String> evidence;
        public final int scannedCount;
        public final boolean truncated;
        Detection(String title, String gameId, String exe, String graphics, String platform,
                  String certainty, String version, String engine, String architecture,
                  List<String> evidence, int scannedCount, boolean truncated) {
            this.title = title;
            this.gameId = gameId;
            this.exe = exe;
            this.graphics = graphics;
            this.platform = platform;
            this.certainty = certainty;
            this.version = version;
            this.engine = engine;
            this.architecture = architecture;
            this.evidence = Collections.unmodifiableList(new ArrayList<>(evidence));
            this.scannedCount = scannedCount;
            this.truncated = truncated;
        }
    }

    private static final Pattern NON_GAME_EXECUTABLE = Pattern.compile(
            "(?i)^(?:unins\\d*|uninstall|install|setup|dxsetup|vcredist(?:_x(?:64|86))?|vc_redist.*|"
            + "unitycrashhandler(?:32|64)?|crash(?:handler|reporter|reportclient).*|"
            + "easyanticheat.*|eaclauncher|epicwebhelper|steam(?:service|webhelper|errorreporter)|"
            + "ubisoftconnect|eadesktop|eaapp|origin|redist.*|prereq.*|updater|"
            + "bugreport.*|.*_crashhandler|.*_helper|.*-win64-shipping-helper)\\.exe$");
    private static final Pattern GENERIC_NAME = Pattern.compile(
            "(?i)^(?:game|game-win64-shipping|game-win32-shipping|ue4game|unreal|unity|"
            + "launcher|start|client|win64|shipping|application|project|my project|windows|"
            + "app|bootstrapper|projectname|test|main)$");

    private static String clean(String x) {
        if (x == null) return "";
        return x.replace('\u0000', ' ').replaceAll("\\s+", " ").trim();
    }
    private static String basename(String path) {
        int p = path.lastIndexOf('/');
        return path.substring(p + 1);
    }
    private static String stem(String name) {
        int i = name.lastIndexOf('.');
        return i > 0 ? name.substring(0, i) : name;
    }
    private static String parent(String path) {
        int p = path.lastIndexOf('/');
        return p <= 0 ? "" : path.substring(0, p);
    }
    private static String normalTitle(String raw) {
        String s = clean(stem(raw));
        s = s.replaceAll("(?i)(?:-win64-shipping|-win32-shipping|_win64|_win32|_shipping)$", "");
        s = s.replace('_', ' ').replace('-', ' ').replace('.', ' ');
        s = s.replaceAll("(?<=[a-z])(?=[A-Z][a-z])", " ");
        s = s.replaceAll("(?i)(?:[ _-]+(?:launcher|bootstrapper|startgame))$", "");
        s = s.replaceAll("(?<=[a-zA-Z])(?=\\d)", " ");
        s = s.replaceAll("(?<=\\d)(?=[a-zA-Z])", " ");
        return clean(s);
    }
    /** Auxiliary programs sometimes embed a trusted-looking ProductName in their EXE.
     * Such names describe the launcher/protection tool, not the containing game.
     * These are component categories, never a catalogue of game titles. */
    private static boolean auxiliaryProduct(String raw) {
        String s = clean(raw).toLowerCase(Locale.ROOT);
        return s.equals("eac") || s.startsWith("eac ") || s.contains("easy anti-cheat") || s.contains("easy anticheat")
                || s.contains("easyanticheat") || s.contains("battleye")
                || s.contains("anti-cheat bootstrapper") || s.contains("anti cheat bootstrapper")
                || s.contains("crash reporter") || s.contains("crash handler")
                || s.contains("redistributable") || s.contains("directx setup");
    }
    private static String comparableName(String raw) {
        return normalTitle(raw).toLowerCase(Locale.ROOT).replaceAll("[^\\p{L}0-9]", "");
    }
    private static boolean nameAgrees(String candidate, String metadataTitle) {
        if (candidate == null || metadataTitle == null || metadataTitle.isEmpty()) return false;
        String a = comparableName(candidate), b = comparableName(metadataTitle);
        return !a.isEmpty() && !b.isEmpty() && (a.equals(b)
                || (a.length() > 6 && b.length() > 6 && (a.startsWith(b) || b.startsWith(a))));
    }
    private static boolean meaningful(String x) {
        String s = clean(x);
        return s.length() >= 3 && s.length() <= 120 && !GENERIC_NAME.matcher(s).matches()
                && !s.equalsIgnoreCase("Microsoft Windows") && !s.equalsIgnoreCase("Unity Player")
                && !s.equalsIgnoreCase("Unreal Engine") && !s.equalsIgnoreCase("Executable")
                && !s.toLowerCase(Locale.ROOT).contains("unreal engine")
                && !auxiliaryProduct(s);
    }
    private static boolean looksLikeGameExe(Entry e) {
        String name = basename(e.path);
        if (e.directory || !name.toLowerCase(Locale.ROOT).endsWith(".exe")) return false;
        if (NON_GAME_EXECUTABLE.matcher(name).matches()) return false;
        String p = e.path.toLowerCase(Locale.ROOT);
        return !p.contains("/redist/") && !p.contains("/_commonredist/")
                && !p.contains("/redistributables/") && !p.contains("/installer/")
                && !p.contains("/support/software/") && !p.contains("/directx/");
    }
    private static int score(Entry e, Set<String> allPaths, String metadataTitle) {
        String lower = e.path.toLowerCase(Locale.ROOT);
        String rawStem = stem(basename(e.path));
        int slash = e.path.length() - e.path.replace("/", "").length();
        int score = 70 - 6 * Math.min(slash, 6);
        if (meaningful(e.productName)) score += 120;
        if (meaningful(e.fileDescription)) score += 45;
        if (auxiliaryProduct(e.productName) || auxiliaryProduct(e.fileDescription)) score -= 210;
        if (nameAgrees(rawStem, metadataTitle)) score += 175;
        if (nameAgrees(basename(parent(e.path)), metadataTitle)) score += 25;
        if (meaningful(normalTitle(rawStem))) score += 25;
        else score -= 45;
        if (e.size > 1_000_000) score += 12;
        if (e.size >= 0 && e.size < 200_000) score -= 15;
        if (lower.contains("/engine/binaries/")) score -= 55;
        if (lower.contains("/binaries/win64/")) score += 18;
        if (lower.contains("/tools/") || lower.contains("/thirdparty/")) score -= 35;
        String normalized = stem(basename(lower));
        for (String path : allPaths) {
            if (path.equals(normalized + "_data") || path.endsWith("/" + normalized + "_data")) {
                score += 30;
                break;
            }
        }
        if (allPaths.contains(normalized + "_data/globalgamemanagers")
                || allPaths.stream().anyMatch(p -> p.endsWith("/" + normalized + "_data/globalgamemanagers")))
            score += 25;
        return score;
    }
    /** Candidate EXEs, ordered by structural likelihood, NOT by a list of known games. */
    public static List<Entry> candidates(List<Entry> entries, int limit) {
        return candidates(entries, limit, "");
    }
    /** Prefer EXEs whose filename agrees with independently read store/engine metadata. */
    public static List<Entry> candidates(List<Entry> entries, int limit, String metadataTitle) {
        if (entries == null || limit <= 0) return Collections.emptyList();
        List<Entry> result = new ArrayList<>();
        for (Entry e : entries) if (e != null && looksLikeGameExe(e)) result.add(e);
        Set<String> paths = new HashSet<>();
        for (Entry e : entries) if (e != null) paths.add(e.path.toLowerCase(Locale.ROOT));
        result.sort(Comparator.comparingInt((Entry e) -> score(e, paths, metadataTitle)).reversed()
                .thenComparing(e -> e.path));
        if (result.size() > limit) return new ArrayList<>(result.subList(0, limit));
        return result;
    }
    private static boolean has(List<Entry> entries, String target) {
        for (Entry e : entries) {
            if (e.directory) continue;
            String p = e.path.toLowerCase(Locale.ROOT);
            if (p.equals(target) || p.endsWith("/" + target)) return true;
        }
        return false;
    }
    private static boolean partial(List<Entry> entries, String fragment) {
        for (Entry e : entries)
            if (!e.directory && e.path.toLowerCase(Locale.ROOT).contains(fragment)) return true;
        return false;
    }
    private static String idFor(String title) {
        String s = Normalizer.normalize(title.toLowerCase(Locale.ROOT), Normalizer.Form.NFKD)
                .replaceAll("[^a-z0-9]+", "-").replaceAll("^-|-$", "");
        return s.isEmpty() ? "unresolved" : s;
    }
    private static String engine(List<Entry> entries, List<String> evidence) {
        boolean unity = false, unreal = false, godot = false, renpy = false;
        for (Entry e : entries) {
            String path = e.path.toLowerCase(Locale.ROOT);
            if (path.endsWith("_data/globalgamemanagers") || path.endsWith("_data/boot.config")
                    || path.endsWith("/unityplayer.dll")) unity = true;
            if (path.contains("/engine/binaries/") || path.endsWith("/engine/build/build.version")
                    || path.matches(".*-win(?:32|64)-shipping\\.exe")) unreal = true;
            if (path.endsWith(".pck") && !path.contains("/engine/")) godot = true;
            if (path.contains("/renpy/") || path.endsWith("/renpy/__init__.py")
                    || path.endsWith("/game/scripts.rpa")) renpy = true;
        }
        int detected = (unity ? 1 : 0) + (unreal ? 1 : 0) + (godot ? 1 : 0) + (renpy ? 1 : 0);
        if (detected != 1) return detected == 0 ? "غير محدد" : "قرائن متعارضة؛ يحتاج فحصاً أعمق";
        String guess = unity ? "Unity" : unreal ? "Unreal Engine" : godot ? "Godot" : "Ren'Py";
        evidence.add("مؤشرات ملفات على محرك " + guess + " (ليس تحققاً من إصدار المحرك)");
        return guess + " (استنتاج من بنية الملفات)";
    }
    private static String graphics(Entry main, List<String> evidence) {
        if (main == null || main.importedDlls.isEmpty())
            return "غير محدد؛ قد يستخدم تحميل DLL ديناميكياً";
        List<String> apis = new ArrayList<>();
        if (main.importedDlls.contains("d3d12.dll")) apis.add("DirectX 12");
        if (main.importedDlls.contains("d3d11.dll")) apis.add("DirectX 11");
        if (main.importedDlls.contains("d3d9.dll")) apis.add("DirectX 9");
        if (main.importedDlls.contains("vulkan-1.dll")) apis.add("Vulkan");
        if (main.importedDlls.contains("opengl32.dll")) apis.add("OpenGL");
        if (apis.isEmpty()) return "لا توجد إشارة مباشرة بجدول imports؛ قد يُحمّل API وقت التشغيل";
        evidence.add("ملف EXE يستورد مكتبات رسومية: " + String.join("، ", apis));
        return String.join(" / ", apis) + " (قرينة من imports، ليست إعداداً معتمداً)";
    }
    public static Detection analyze(List<Entry> entries, boolean truncated) {
        return analyze(entries, truncated, GameManifestReader.analyze(Collections.emptyList()));
    }
    public static Detection analyze(List<Entry> entries, boolean truncated, GameManifestReader.Result metadata) {
        if (entries == null) entries = Collections.emptyList();
        List<String> evidence = new ArrayList<>();
        List<Entry> matches = candidates(entries, 2, metadata == null ? "" : metadata.title);
        String title = "لعبة غير معروفة", id = "unresolved", exe = "";
        String certainty = "غير محدد", version = "غير محدد";
        Entry mainExe = null;
        if (!matches.isEmpty()) {
            Entry main = matches.get(0);
            mainExe = main;
            exe = main.path;
            String best = "";
            if (meaningful(main.productName)) {
                best = main.productName;
                certainty = "مرتفع: بيانات ProductName داخل ملف EXE";
                evidence.add("اسم المنتج من بيانات EXE: " + best);
            } else if (meaningful(main.fileDescription)) {
                best = main.fileDescription;
                certainty = "متوسط: وصف ملف EXE";
                evidence.add("وصف من بيانات EXE: " + best);
            } else if (meaningful(normalTitle(basename(exe)))) {
                best = normalTitle(basename(exe));
                certainty = "متوسط/منخفض: اسم ملف التشغيل (استنتاج)";
                evidence.add("اسم مستنتج من EXE، وليس تأكيد هوية: " + best);
            } else {
                String dirName = basename(parent(exe));
                if (meaningful(normalTitle(dirName))) {
                    best = normalTitle(dirName);
                    certainty = "منخفض: اسم مجلد اللعبة (استنتاج)";
                    evidence.add("اسم مستنتج من المجلد: " + best);
                }
            }
            if (!best.isEmpty()) { title = best; id = idFor(title); }
            boolean componentIdentity = auxiliaryProduct(main.productName)
                    || auxiliaryProduct(main.fileDescription);
            if (componentIdentity) {
                evidence.add("تنبيه: بيانات EXE تعود إلى أداة حماية/مساعدة ("
                        + (main.productName.isEmpty() ? main.fileDescription : main.productName)
                        + ")، وليست دليلاً على اسم اللعبة أو إصدارها");
            }
            if (!main.productVersion.isEmpty()) {
                if (componentIdentity) {
                    evidence.add("إصدار برنامج الحماية/المشغّل: " + main.productVersion
                            + " (ليس إصدار اللعبة)");
                } else {
                    version = main.productVersion;
                    evidence.add("إصدار ملف EXE المعلن: " + version + " (قد يختلف عن إصدار اللعبة)");
                }
            }
            if (!main.importedDlls.isEmpty()) evidence.add("مكتبات PE المستوردة (مباشرة): " + String.join("، ", main.importedDlls));
            evidence.add("مرشح التشغيل الأول: " + exe);
            if (matches.size() > 1) evidence.add("توجد ملفات EXE إضافية؛ يجب تأكيد ملف التشغيل إذا كان الاختيار خاطئاً");
        } else evidence.add("لم يُعثر على ملف تشغيل مناسب ضمن العناصر التي تمت قراءتها");
        if (metadata != null && !metadata.title.isEmpty()) {
            // A game title stored in a store/engine manifest outranks metadata belonging to
            // an anti-cheat bootstrapper or other helper, even when it has ProductName.
            boolean strongExeName = mainExe != null && meaningful(mainExe.productName);
            boolean reliableManifest = metadata.confidence >= 75;
            if (reliableManifest || !strongExeName) {
                if (!title.equalsIgnoreCase(metadata.title) && !title.equals("لعبة غير معروفة"))
                    evidence.add("تعارض محتمل بين اسم EXE وبيانات تعريف اللعبة؛ تم اعتماد المصدر المحلي: "
                            + metadata.evidenceSource);
                title = metadata.title; id = idFor(title);
                certainty = "مرتفع نسبياً: " + metadata.evidenceSource + " (بيانات محلية)";
            } else if (!title.equalsIgnoreCase(metadata.title)) {
                evidence.add("تعارض بين بيانات EXE وبيانات ملفات المنصة: " + metadata.title);
            }
            if (version.equals("غير محدد") && !metadata.version.isEmpty()) {
                version = metadata.version;
                evidence.add("رقم بناء من بيانات المنصة؛ قد يختلف عن إصدار اللعبة: " + version);
            }
        }
        if (metadata != null) evidence.addAll(metadata.evidence);
        String platform = "غير معروف؛ لا يمكن الجزم بأنها مستقلة";
        Set<String> imports = mainExe == null ? Collections.emptySet() : new HashSet<>(mainExe.importedDlls);
        if (has(entries, "steam_appid.txt") || partial(entries, "appmanifest_")) {
            platform = "Steam (قرينة؛ لا تثبت الترخيص أو وجوب تشغيل Steam)";
            evidence.add("ملف تعريف Steam محتمل");
        } else if (has(entries, "steam_api64.dll") || has(entries, "steam_api.dll")
                || imports.contains("steam_api64.dll") || imports.contains("steam_api.dll")) {
            platform = "Steam (احتمال ضعيف؛ وجود DLL لا يثبت الاعتماد على Steam)";
        } else if (has(entries, "upc_r2_loader.dll") || partial(entries, "uplay_r1_loader")
                || imports.contains("upc_r2_loader.dll")) {
            platform = "Ubisoft Connect (احتمال)";
        } else if (has(entries, "socialclub.dll") || has(entries, "socialclub64.dll")) {
            platform = "Rockstar Games Launcher (احتمال)";
        } else if (has(entries, "originclient.dll") || partial(entries, "eaappinstaller")) {
            platform = "EA app (احتمال)";
        } else if (has(entries, "eossdk-win64-shipping.dll") || imports.contains("eossdk-win64-shipping.dll")) {
            platform = "Epic Online Services (قرينة على خدمة، لا تحدد متجر الشراء)";
        }
        if (metadata != null && !metadata.platform.isEmpty()) platform = metadata.platform;
        if (partial(entries, "easyanticheat") || partial(entries, "easyanticheat_eos")
                || partial(entries, "easy anti-cheat")) {
            evidence.add("مؤشر على Easy Anti-Cheat داخل المجلد؛ التشغيل عبر Wine/Proton غير مضمون،"
                    + " ويتوقف على دعم المطور للحماية على Linux/Proton");
        }
        String engine = engine(entries, evidence);
        if (engine.equals("غير محدد") && mainExe != null
                && mainExe.importedDlls.contains("unityplayer.dll")) {
            engine = "Unity (قرينة من PE imports)";
            evidence.add("EXE يستورد UnityPlayer.dll؛ قرينة لمحرك Unity");
        }
        String graphics = graphics(mainExe, evidence);
        String architecture = mainExe == null ? "غير محدد" : mainExe.architecture;
        if (truncated) evidence.add("الفحص غير شامل؛ قد توجد ملفات لم تُقرأ");
        evidence.add("متطلبات CPU/RAM/Windows ونسخة DirectX الموصى بها لا يمكن إثباتها من EXE وحده؛ تحتاج بيانات المطور الرسمي أو قاعدة متطلبات موثوقة");
        evidence.add("لا توجد إعدادات Proton/FEX/VKD3D/Turnip معتمدة قبل اختبار التوافق");
        return new Detection(title, id, exe, graphics, platform, certainty, version, engine, architecture,
                evidence, entries.size(), truncated);
    }
}
