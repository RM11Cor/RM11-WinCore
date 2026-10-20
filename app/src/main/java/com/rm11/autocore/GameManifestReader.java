package com.rm11.autocore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only identification from local metadata that ships with arbitrary games.
 * No catalogue of game titles, no online lookups and no attempt to execute files.
 * Input is a capped excerpt of a SMALL, allowlisted metadata file.
 */
public final class GameManifestReader {
    private GameManifestReader() { }
    public static final int MAX_BYTES = 64 * 1024;
    public static final int MAX_DOCUMENTS = 160;

    public static final class Document {
        public final String path, content;
        public Document(String path, String content) {
            this.path = path == null ? "" : path.replace('\\', '/');
            this.content = content == null ? "" : content.substring(0, Math.min(content.length(), MAX_BYTES));
        }
    }
    public static final class Result {
        public final String title, version, platform, steamAppId, evidenceSource;
        public final int confidence;
        public final List<String> evidence;
        Result(String title, String version, String platform, String steamAppId,
               String evidenceSource, int confidence, List<String> evidence) {
            this.title = title; this.version = version; this.platform = platform;
            this.steamAppId = steamAppId; this.evidenceSource = evidenceSource;
            this.confidence = confidence;
            this.evidence = Collections.unmodifiableList(new ArrayList<>(evidence));
        }
    }

    private static boolean ends(String path, String suffix) { return path.endsWith(suffix); }
    public static boolean accepts(String nameOrPath, long size) {
        if (nameOrPath == null || size > MAX_BYTES || size == 0) return false;
        String p = nameOrPath.replace('\\', '/').toLowerCase(Locale.ROOT);
        String name = p.substring(p.lastIndexOf('/') + 1);
        if (name.matches("appmanifest_[0-9]+\\.acf")) return true;
        if (name.equals("steam_appid.txt")) return true;
        if (name.matches("goggame-[0-9]+\\.info")) return true;
        if (name.equals("app.info") && p.contains("_data/")) return true;
        if (name.equals("defaultgame.ini") && (p.contains("/config/") || p.startsWith("config/"))) return true;
        if (name.endsWith(".uproject")) return true;
        if (name.endsWith(".item") && p.contains(".egstore/")) return true;
        return false;
    }

    private static String value(String input, String key) {
        String re = "(?im)[\\\"']?" + Pattern.quote(key) + "[\\\"']?\\s*[:=]\\s*[\\\"']?([^\\\"'\\r\\n,}]+)";
        Matcher m = Pattern.compile(re).matcher(input);
        if (!m.find()) return "";
        return valid(m.group(1));
    }
    private static String valid(String s) {
        if (s == null) return "";
        s = s.replace("\\\\\"", "\"").replace("\\\\/", "/")
                .replaceAll("[\\p{Cntrl}]", " ").replaceAll("\\s+", " ").trim();
        if (s.length() > 120 || s.length() < 2 || s.equalsIgnoreCase("None")
                || s.equalsIgnoreCase("Game") || s.equalsIgnoreCase("Project")) return "";
        return s;
    }
    private static String fromQuoted(String text, String key) {
        // Steam ACF: "name" "Game"; JSON: "DisplayName": "Game"; INI: ProjectName=Game.
        Matcher m = Pattern.compile("(?im)^[ \\t]*\\\"?" + Pattern.quote(key)
                + "\\\"?[ \\t]*[:=]?[ \\t]*\\\"([^\\\"\\r\\n]{2,120})\\\"").matcher(text);
        return m.find() ? valid(m.group(1)) : value(text, key);
    }
    private static String numeric(String x) { return x != null && x.matches("[0-9]{3,16}") ? x : ""; }
    private static String stem(String p) {
        String n = p.substring(p.lastIndexOf('/') + 1);
        int i = n.lastIndexOf('.'); return i > 0 ? n.substring(0, i) : n;
    }
    private static final class Hint {
        String name, source, platform, version, steamId;
        int weight;
        Hint(String n, String s, String p, String v, String id, int w) {
            name=n; source=s; platform=p; version=v; steamId=id; weight=w;
        }
    }

    public static Result analyze(List<Document> files) {
        if (files == null) files = Collections.emptyList();
        List<Hint> hints = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        String steamId = "";
        boolean steamManifest = false;
        String platform = "";
        int count = 0;
        for (Document doc : files) {
            if (doc == null || !accepts(doc.path, doc.content.length()) || count++ >= MAX_DOCUMENTS) continue;
            String path = doc.path.toLowerCase(Locale.ROOT);
            String file = path.substring(path.lastIndexOf('/') + 1);
            String data = doc.content;
            String title = "", version = "", source = "", kind = "";
            int score = 0;
            if (file.matches("appmanifest_[0-9]+\\.acf")) {
                title = fromQuoted(data, "name"); version = fromQuoted(data, "buildid");
                steamId = numeric(fromQuoted(data, "appid"));
                if (steamId.isEmpty()) steamId = numeric(file.substring("appmanifest_".length(), file.length() - 4));
                steamManifest = true; source="Steam appmanifest"; kind="Steam"; score=95;
            } else if (file.equals("steam_appid.txt")) {
                String id = numeric(data.trim());
                if (!id.isEmpty() && steamId.isEmpty()) steamId = id;
                evidence.add("معرّف Steam محلي: " + (id.isEmpty() ? "غير صالح" : id) + "؛ لا يثبت الترخيص");
                continue;
            } else if (file.startsWith("goggame-") && file.endsWith(".info")) {
                title=fromQuoted(data,"name"); version=fromQuoted(data,"version");
                source="GOG game info"; kind="GOG"; score=94;
            } else if (file.endsWith(".item") && path.contains(".egstore/")) {
                title=fromQuoted(data,"DisplayName"); version=fromQuoted(data,"AppVersionString");
                source="Epic .egstore metadata"; kind="Epic Games Store"; score=93;
            } else if (file.equals("app.info") && path.contains("_data/")) {
                String[] lines=data.split("\\r?\\n",4);
                if(lines.length >= 2) title=valid(lines[1]);
                source="Unity app.info"; score=85;
            } else if (file.equals("defaultgame.ini")) {
                Matcher m = Pattern.compile("(?im)^\\s*ProjectDisplayedTitle\\s*=\\s*NSLOCTEXT\\([^,]+,[^,]+,\\s*\\\"([^\\\"]+)\\\"\\s*\\)").matcher(data);
                title=m.find()?valid(m.group(1)):fromQuoted(data,"ProjectDisplayedTitle");
                if (title.isEmpty()) title=fromQuoted(data,"ProjectName");
                source="Unreal Config/DefaultGame.ini"; score=78;
            } else if (file.endsWith(".uproject")) {
                title=valid(stem(doc.path)); source="Unreal .uproject file"; score=53;
            }
            if (!title.isEmpty()) {
                hints.add(new Hint(title,source,kind,version,steamId,score));
                evidence.add("اسم من " + source + ": " + title + " (بيانات محلية، قد تختلف عن الإصدار الرسمي)");
            }
            if (!kind.isEmpty() && platform.isEmpty()) platform=kind;
        }
        Hint winner = null;
        for (Hint h : hints) if (winner==null || h.weight>winner.weight) winner=h;
        if (steamManifest) platform="Steam (قرينة من appmanifest؛ لا يثبت الترخيص)";
        else if (platform.equals("Steam")) platform="Steam (قرينة؛ لا يثبت الترخيص)";
        else if (!platform.isEmpty()) platform += " (معلومات محلية؛ لا تثبت امتلاك اللعبة)";
        if (!steamId.isEmpty()) evidence.add("Steam AppID المستخرج: " + steamId + "؛ يصلح للبحث في قاعدة المتطلبات لاحقاً");
        return new Result(winner==null?"":winner.name, winner==null?"":winner.version,
                platform,steamId,winner==null?"":winner.source,
                winner==null?0:winner.weight,evidence);
    }
}
