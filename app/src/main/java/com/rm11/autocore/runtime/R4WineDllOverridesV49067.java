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

    /** Per-game D3D12 routing; preserves independent XInput/Winebus directives. */
    public static String forDx12(String existing) {
        List<String> kept=new ArrayList<>();
        if(existing!=null)for(String raw:existing.split(";",-1)){
            String entry=raw.trim();
            if(entry.isEmpty())continue;
            int equals=entry.indexOf('=');
            if(equals<=0){kept.add(entry);continue;}
            String[] candidates=entry.substring(0,equals).split(",");
            List<String> remaining=new ArrayList<>();
            for(String n:candidates){
                String name=n.trim().toLowerCase(Locale.ROOT);
                if(name.equals("d3d12")||name.equals("d3d12.dll")
                   ||name.equals("d3d12core")||name.equals("d3d12core.dll")
                   ||name.equals("dxgi")||name.equals("dxgi.dll")
                   ||name.equals("d3d11")||name.equals("d3d11.dll"))continue;
                if(!n.trim().isEmpty())remaining.add(n.trim());
            }
            if(!remaining.isEmpty())kept.add(String.join(",",remaining)+entry.substring(equals));
        }
        kept.add("d3d12,d3d12core,dxgi=n,b");
        kept.add("d3d11=b");
        return String.join(";",kept);
    }

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
