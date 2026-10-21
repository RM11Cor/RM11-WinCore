package com.rm11.autocore;

/** Strict prerequisites, NOT a claim of end-to-end Windows executable compatibility. */
public final class RuntimePrerequisites {
    private RuntimePrerequisites() { }

    public static boolean allVerified(boolean nativeExecutionWorks,
                                      boolean translatorIntegrated,
                                      boolean windowsLayerIntegrated,
                                      boolean graphicsBridgeIntegrated,
                                      boolean gameFileAccessVerified) {
        return nativeExecutionWorks && translatorIntegrated && windowsLayerIntegrated
                && graphicsBridgeIntegrated && gameFileAccessVerified;
    }
}
