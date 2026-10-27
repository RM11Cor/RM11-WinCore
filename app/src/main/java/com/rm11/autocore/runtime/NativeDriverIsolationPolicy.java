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
 * One bounded v4.0.67 retest of the game-specific Vulkan-loader isolation after an observed Qualcomm
 * Adreno shader-compiler abort. Disables only RM11's experimental Android
 * libvulkan.so fallback for that ONE retest using a version-specific marker; never changes drivers, Android,
 * Wine/FEX, graphics cache, game saves, DXVK or the Wine prefix.
 */
public final class NativeDriverIsolationPolicy {
    private static final Pattern TIME=Pattern.compile(
            "\"timeUnixMs\"\\s*:\\s*([0-9]{10,16})");
    private static final String MARKER="v470-actionable-seh-capture-consumed.txt";
    private static final String EVIDENCE="last-game-seh.json";

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
                    "RM11_V462_SEH_FATAL_EVENT_SEEN=true")
                || !evidence.contains(
                    "Unhandled exception: page fault on read access to 0x0000000000000070")
                || !evidence.contains("RM11_V468_FATAL_PC=00006ffeb1d0d0")
                || !evidence.contains("RM11_V463_ASSERT_RIP_IMAGE=ANONYMOUS_EXECUTABLE"))
            return false;
        Matcher m=TIME.matcher(evidence);
        if(!m.find())return false;
        String stamp=m.group(1);
        // One isolation run total for this signed v4.0.66 feature, even if
        // the isolated process emits a NEW crash timestamp.
        return marker==null||marker.trim().isEmpty();
    }

    public static Decision evaluate(Path diagnosticDir,String gameName) {
        try {
            Path snapshot=diagnosticDir.resolve(EVIDENCE);
            Path marker=diagnosticDir.resolve(MARKER);
            if(!Files.isRegularFile(snapshot,LinkOption.NOFOLLOW_LINKS)
                    ||Files.isSymbolicLink(marker)
                    ||Files.size(snapshot)<60 ||Files.size(snapshot)>18000)
                return new Decision(false,"","NO_VALID_PRIOR_DRIVER_ABORT");
            String body=new String(Files.readAllBytes(snapshot),StandardCharsets.UTF_8);
            Path v467=diagnosticDir.resolve("last-v467-isolation.json");
            if(!Files.isRegularFile(v467,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(v467)<80||Files.size(v467)>18000)
                return new Decision(false,"","V467_OFF_RECORD_UNAVAILABLE");
            String previousTrial=new String(Files.readAllBytes(v467),StandardCharsets.UTF_8);
            if(!previousTrial.contains("\"test\":\"v467-silksong-off-retest\"")
                    ||!previousTrial.contains("RM11_V467_VULKAN_FALLBACK=OFF")
                    ||!previousTrial.contains("RM11_V467_CONSUMED_MARKER_WRITTEN=true"))
                return new Decision(false,"","V467_OFF_NOT_CONFIRMED");
            Matcher m=TIME.matcher(body);
            if(!m.find())return new Decision(false,"","NO_EVIDENCE_TIMESTAMP");
            String stamp=m.group(1);
            String previous="";
            if(Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS)
                    &&Files.size(marker)<80)
                previous=new String(Files.readAllBytes(marker),StandardCharsets.UTF_8);
            if(!shouldIsolate(body,previous,gameName))
                return new Decision(false,stamp,"NOT_ELIGIBLE_OR_ALREADY_TESTED");
            return new Decision(true,stamp,"V469_ANONYMOUS_FAULT_CAPTURE_RETEST");
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
            Files.write(temp,decision.sourceTimestamp.getBytes(StandardCharsets.UTF_8));
            Files.move(temp,marker,StandardCopyOption.REPLACE_EXISTING);
            return true;
        }catch(IOException|SecurityException denied){return false;}
    }
}
