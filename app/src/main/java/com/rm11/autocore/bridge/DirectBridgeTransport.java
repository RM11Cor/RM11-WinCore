package com.rm11.autocore.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONObject;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * Opt-in, app-only, outbound HTTPS diagnostic bridge. No shell commands,
 * other app access, or background telemetry. Pairing is revocable.
 */
public final class DirectBridgeTransport {
    private static final String SERVICE = "https://rm11-directbridge-relay.vercel.app/ingest";
    private static final String PREFS = "rm11-directbridge-pairing";
    private static final String KEY = "device-code";
    private static final String ENABLED = "enabled";
    private static final SecureRandom RNG = new SecureRandom();
    private DirectBridgeTransport() {}

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
    private static byte[] decodeHex(String code) {
        if (code == null || !code.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid device access code");
        byte[] b = new byte[32];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(code.substring(i*2, i*2+2), 16);
        }
        return b;
    }

    /** One long random key is generated locally and never checked into GitHub. */
    public static synchronized String enablePairing(Context ctx) {
        SharedPreferences p = prefs(ctx);
        String current = p.getString(KEY, null);
        if (current == null || !current.matches("[a-f0-9]{64}")) {
            byte[] key = new byte[32];
            RNG.nextBytes(key);
            StringBuilder hex = new StringBuilder(64);
            for (byte b : key) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff));
            Arrays.fill(key, (byte)0);
            current = hex.toString();
        }
        boolean saved = p.edit().putString(KEY, current).putBoolean(ENABLED, true).commit();
        if (!saved) throw new IllegalStateException("Could not save pairing state");
        return current;
    }

    public static boolean enabled(Context ctx) { return prefs(ctx).getBoolean(ENABLED, false); }

    public static String pairingCode(Context ctx) {
        return enabled(ctx) ? prefs(ctx).getString(KEY, null) : null;
    }

    /** Disables uploads and rotates away the pairing key. Any old server copy expires separately. */
    public static synchronized void revoke(Context ctx) {
        if (!prefs(ctx).edit().clear().commit()) throw new IllegalStateException("Could not revoke pairing locally");
    }

    /** Compact, redacted diagnostic; never transfer entire Wine logs, game folders or secrets. */
    private static JSONObject collect(Context ctx) throws Exception {
        Path file = new File(new File(ctx.getFilesDir(), "directbridge"), "last-wine-smoke.json").toPath();
        if (!Files.isRegularFile(file) || Files.isSymbolicLink(file) || Files.size(file) > 300000)
            throw new IllegalStateException("No valid saved RM11 Wine diagnostic");
        JSONObject saved = new JSONObject(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
        JSONObject result = new JSONObject();
        result.put("schema", "rm11.directbridge.smoke.v1");
        result.put("capturedAtUnixMs", saved.optLong("capturedAtUnixMs", 0));
        result.put("resultCode", saved.optString("resultCode", "UNKNOWN"));
        result.put("summary", saved.optString("summary", "").substring(0,
                Math.min(700, saved.optString("summary", "").length())));
        result.put("wineServerAliveAtClientExit", saved.optBoolean("wineServerAliveAtClientExit", false));
        result.put("nlsRedirectObserved", saved.optBoolean("nlsRedirectObserved", false));
        result.put("uiCaptureTruncated", saved.optBoolean("uiCaptureTruncated", false));
        result.put("rootCauseConfirmed", false);
        result.put("runtimeFiles", saved.optJSONObject("runtimeFiles"));
        // Only a compact excerpt: redact obvious tokens, home path names and settings secrets.
        String raw = saved.optString("wineReport", "");
        String excerpt = raw.substring(Math.max(0, raw.length() - 15000));
        excerpt = excerpt.replaceAll("(?i)(authorization|password|passwd|token|secret|cookie)(\\s*[:=]\\s*)[^\\s\\r\\n]+", "$1$2[REDACTED]");
        excerpt = excerpt.replaceAll("(?i)/storage/emulated/[0-9]+/[^\\s\\\"']+", "[REDACTED_STORAGE_PATH]");
        excerpt = excerpt.replaceAll("(?i)/sdcard/[^\\s\\\"']+", "[REDACTED_STORAGE_PATH]");
        result.put("wineLogTail", excerpt);
        return result;
    }

    /**
     * Call on worker thread after explicit opt-in. AES-256-GCM payload carries
     * nonce + ciphertext + tag; HTTPS also protects the device access code.
     */
    public static String uploadLast(Context ctx) {
        if (!enabled(ctx)) return "PAIRING_DISABLED";
        HttpsURLConnection connection = null;
        byte[] key = null;
        try {
            String code = pairingCode(ctx);
            key = decodeHex(code);
            JSONObject compact = collect(ctx);
            byte[] plaintext = compact.toString().getBytes(StandardCharsets.UTF_8);
            if (plaintext.length > 54000) return "REPORT_TOO_LARGE";
            byte[] nonce = new byte[12];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128, nonce));
            byte[] sealed = cipher.doFinal(plaintext);
            ByteArrayOutputStream encoded = new ByteArrayOutputStream(nonce.length + sealed.length);
            encoded.write(nonce);
            encoded.write(sealed);
            JSONObject body = new JSONObject();
            body.put("code", code);
            body.put("encrypted", android.util.Base64.encodeToString(encoded.toByteArray(), android.util.Base64.NO_WRAP));
            byte[] post = body.toString().getBytes(StandardCharsets.UTF_8);
            if (post.length > 65000) return "ENCRYPTED_REPORT_TOO_LARGE";

            URL endpoint = new URL(SERVICE);
            if (!"https".equals(endpoint.getProtocol())
                    || !"rm11-directbridge-relay.vercel.app".equals(endpoint.getHost()))
                return "INVALID_ENDPOINT";
            connection = (HttpsURLConnection) endpoint.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(15000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setFixedLengthStreamingMode(post.length);
            try(OutputStream out=connection.getOutputStream()) {out.write(post);}
            int response = connection.getResponseCode();
            // Never log server response bodies; they might contain proxy-auth HTML.
            if (response == 200) return "UPLOAD_ACCEPTED";
            if (response == 403) return "PAIRING_NOT_APPROVED_OR_PROTECTED";
            if (response == 401) return "VERCEL_AUTH_REQUIRED";
            if (response == 503) return "BRIDGE_STORAGE_NOT_READY";
            return "HTTP_" + response;
        } catch (Exception ex) {
            return "UPLOAD_ERROR_" + ex.getClass().getSimpleName();
        } finally {
            if (key != null) Arrays.fill(key,(byte)0);
            if (connection != null) connection.disconnect();
        }
    }
}
