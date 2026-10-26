package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One bounded, game-specific counterfactual run after an observed Qualcomm
 * Adreno shader-compiler abort. Disables only RM11's experimental Android
 * libvulkan.so fallback for that ONE run; never changes drivers, Android,
 * Wine/FEX, graphics cache, game saves, DXVK or the Wine prefix.
 */
public final class NativeDriverIsolationPolicy {
    private static final Pattern TIME=Pattern.compile(
            "\"timeUnixMs\"\\s*:\\s*([0-9]{10,16})");
    private static final String MARKER="v466-driver-isolation-consumed.txt";
    private static final String EVIDENCE="last-native-abort.json";

    public static final class Decision {
        public final boolean isolate;
        public final String sourceTimestamp;
        public final String reason;
        private Decision(boolean yes,String at,String why) {
            isolate=yes;sourceTimestamp=at;reason=why;
        }
    }

    private NativeDriverIsolationPolicy() {}

    public static boolean shouldIsolate(String evidence,String marker,String gameName) {
        if(gameName==null || !gameName.equalsIgnoreCase("Hollow Knight Silksong.exe"))
            return false;
        if(evidence==null || !evidence.contains(
                    "RM11_V465_NATIVE_ABORT_CALLER_SEEN=true")
                || !evidence.contains(
                    "RM11_V465_NATIVE_ABORT_CALLER_IMAGE=libllvm-glnext.so"))
            return false;
        Matcher m=TIME.matcher(evidence);
        if(!m.find())return false;
        String stamp=m.group(1);
        return marker==null||!marker.trim().equals(stamp);
    }

    public static Decision evaluate(Path diagnosticDir,String gameName) {
        try {
            Path snapshot=diagnosticDir.resolve(EVIDENCE);
            Path marker=diagnosticDir.resolve(MARKER);
            if(!Files.isRegularFile(snapshot,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(marker)
                    ||Files.size(snapshot)<60 ||Files.size(snapshot)>18000)
                return new Decision(false,"","NO_VALID_PRIOR_DRIVER_ABORT");
            String body=Files.readString(snapshot,StandardCharsets.UTF_8);
            Matcher m=TIME.matcher(body);
            if(!m.find())return new Decision(false,"","NO_EVIDENCE_TIMESTAMP");
            String stamp=m.group(1);
            String previous="";
            if(Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS)
                    &&Files.size(marker)<80)
                previous=Files.readString(marker,StandardCharsets.UTF_8);
            if(!shouldIsolate(body,previous,gameName))
                return new Decision(false,stamp,"NOT_ELIGIBLE_OR_ALREADY_TESTED");
            return new Decision(true,stamp,"CONFIRMED_ADRENO_NATIVE_ABORT");
        }catch(IOException|SecurityException invalid) {
            return new Decision(false,"","PRIVATE_SNAPSHOT_UNAVAILABLE");
        }
    }

    public static boolean commitOnce(Path diagnosticDir,Decision decision) {
        if(decision==null||!decision.isolate)return false;
        try {
            if(!Files.isDirectory(diagnosticDir,LinkOption.NOFOLLOW_LINKS))
                return false;
            Path marker=diagnosticDir.resolve(MARKER);
            Path temp=diagnosticDir.resolve(MARKER+".pending");
            if(Files.isSymbolicLink(marker)||Files.isSymbolicLink(temp))
                return false;
            Files.writeString(temp,decision.sourceTimestamp,StandardCharsets.UTF_8);
            Files.move(temp,marker,StandardCopyOption.REPLACE_EXISTING);
            return true;
        }catch(IOException|SecurityException denied){return false;}
    }
}
