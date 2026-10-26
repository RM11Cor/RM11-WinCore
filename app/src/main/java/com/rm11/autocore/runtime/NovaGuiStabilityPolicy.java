package com.rm11.autocore.runtime;

/**
 * REDMAGIC on-device evidence v4.0.38:
 * - Winefile's first-start opt-in win32u client was active.
 * - The native wineserver exited with code 1 and logged "wineserver crashed".
 * - A concurrently selected FreeType probe had no verified window or exit.
 *
 * Correlation is not proof of causation. Until a fix has on-device proof,
 * fail closed on all spontaneous/interactive font-loader experiments.
 * Stable Winefile, unchanged Windows clients and preserved prefix are safer.
 */
public final class NovaGuiStabilityPolicy {
    private NovaGuiStabilityPolicy(){}

    public static boolean allowAutomaticWinefileFontClient(){
        return false;
    }

    public static boolean allowManualExeFontProbe(){
        return false;
    }

    public static String summary(){
        return "RM11_V439_DEFAULT_WINEFILE_PATCHED_FONTCLIENT_DISABLED=true\n"
                +"RM11_V439_EXE_FREETYPE_TRIAL_DISABLED=true\n"
                +"RM11_V439_GAMES_AND_WINESERVER_FONTS_UNMODIFIED=true\n"
                +"RM11_V439_FONT_ROOT_CAUSE_NOT_YET_VERIFIED=true";
    }
}
