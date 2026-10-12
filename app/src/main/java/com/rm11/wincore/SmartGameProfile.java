package com.rm11.wincore;

import java.util.Locale;

/**
 * Initial offline suggestions, NOT a runtime auto-tuner and NOT compatibility proof.
 * Actual best quality/FPS requires engine integration, frame pacing, thermal data and tests.
 */
public final class SmartGameProfile {
    private SmartGameProfile() {}

    public static String recommend(WindowsExecutableAnalyzer.Result info) {
        StringBuilder s = new StringBuilder("RM11 WinCore V0.5 / Smart Balance (PREVIEW)\n");
        s.append("READ ONLY — no EXE execution, no Wine/Box64 installed.\n\n");
        s.append("File: ").append(info.fileName).append('\n');
        s.append("Architecture: ").append(info.architecture()).append('\n');
        s.append("Sections: ").append(info.sectionCount).append('\n');
        s.append("Graphics API hint (static import table): ").append(info.graphicsHint).append('\n');
        s.append("Imports inspected: ").append(info.importedLibraries.size()).append('\n');
        s.append("Import table complete in sample: ").append(info.importsFullyVisible ? "probably" : "NO / not available").append('\n');
        if (!info.importedLibraries.isEmpty()) {
            s.append("Selected imports: ");
            int count = 0;
            for (String dll : info.importedLibraries) {
                if (count++ > 0) s.append(", ");
                s.append(dll);
                if (count >= 12) { s.append(" …"); break; }
            }
            s.append('\n');
        }
        s.append('\n');
        if (info.dll) s.append("[CAUTION] This is a DLL, not an independently launchable game.\n");
        if (info.machine == 0x014c) s.append("[CAUTION] x86-32 requires a 32-bit compatibility route not integrated here.\n");
        else if (info.machine == 0x8664) s.append("[REQUIRES] Wine + Box64 for x64 on ARM64.\n");
        else s.append("[CAUTION] Unvalidated CPU architecture for this engine.\n");
        String pipeline;
        int width = 1280, height = 720, fps = 30;
        String quality = "Low-Medium";
        switch (info.graphicsHint) {
            case "D3D12":
                pipeline = "Future Wine + VKD3D-Proton -> Vulkan";
                fps = 30;
                break;
            case "D3D11":
            case "D3D10":
                pipeline = "Future Wine + DXVK -> Vulkan";
                fps = 60;
                break;
            case "D3D9":
                pipeline = "Future Wine + DXVK -> Vulkan (when suitable)";
                width = 1600; height = 900; fps = 60; quality = "Medium";
                break;
            case "Vulkan":
                pipeline = "Future Wine Vulkan bridge / graphics integration";
                fps = 60;
                break;
            case "OpenGL":
                pipeline = "Future Wine OpenGL translation";
                fps = 60;
                break;
            default:
                pipeline = "Auto-detect at launch AFTER engine integration";
        }
        s.append("\nInitial balanced profile (NOT measured FPS):\n");
        s.append(String.format(Locale.US, "Resolution: %dx%d\nTarget FPS: %d\n", width, height, fps));
        s.append("Graphics starting quality: ").append(quality).append('\n');
        s.append("Possible graphics path: ").append(pipeline).append('\n');
        s.append("GPU baseline: stock Adreno 840; do not promise a Turnip improvement.\n");
        s.append("[LIMIT] Static imports can miss dynamic DLL loading, and cannot establish a game's identity, anti-cheat support or performance.\n");
        s.append("[NOT ACTIVE] Automatic quality/FPS/temperature adjustments need a working game engine and live measurements.\n");
        return s.toString();
    }
}
