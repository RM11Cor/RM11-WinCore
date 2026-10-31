package com.rm11.autocore.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * R4 v4.90.67: only replace the D3D11/DXGI graphics directives of a selected
 * game's Wine launch environment. Never overwrite XInput, Winebus or other
 * DLL overrides in the shared controller pipeline.
 *
 * Wine's WINEDLLOVERRIDES groups are semicolon separated, and each group may
 * contain a comma-separated DLL name list before '=flags'.
 */
public final class R4WineDllOverridesV49067 {
    private R4WineDllOverridesV49067() {}

    public static String forGameGraphics(String existing, boolean dxvk) {
        List<String> kept = new ArrayList<>();
        if (existing != null && !existing.isEmpty()) {
            for (String raw : existing.split(";", -1)) {
                String entry = raw.trim();
                if (entry.isEmpty()) continue;
                int equals = entry.indexOf('=');
                if (equals <= 0) {
                    // Malformed/opaque entries are preserved rather than lost.
                    kept.add(entry);
                    continue;
                }
                String names = entry.substring(0, equals);
                String flags = entry.substring(equals + 1);
                List<String> retainedNames = new ArrayList<>();
                for (String rawName : names.split(",", -1)) {
                    String name = rawName.trim();
                    String lower = name.toLowerCase(Locale.ROOT);
                    if (lower.equals("d3d11") || lower.equals("d3d11.dll")
                        || lower.equals("dxgi") || lower.equals("dxgi.dll")) {
                        continue;
                    }
                    if (!name.isEmpty()) retainedNames.add(name);
                }
                if (!retainedNames.isEmpty()) {
                    kept.add(String.join(",", retainedNames) + "=" + flags);
                }
            }
        }
        kept.add(dxvk ? "d3d11,dxgi=n,b" : "d3d11,dxgi=b");
        return String.join(";", kept);
    }
}
