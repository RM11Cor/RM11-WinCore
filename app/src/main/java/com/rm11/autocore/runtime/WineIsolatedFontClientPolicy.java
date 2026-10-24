package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Android 16 signed native-library boundary for the v4.0.6 client experiment.
 * The tested Winefile may load a private modified win32u; wineserver and
 * explorer retain the device-proven v4.0.5 native win32u and cannot see a
 * process-wide generic libfreetype.so alias.
 */
public final class WineIsolatedFontClientPolicy {
    private WineIsolatedFontClientPolicy() {}

    private static boolean trustedElf(RuntimeLayout p,String filename,long minimum) {
        try {
            Path nativeHome=p.apkNativeLibs.toRealPath();
            Path file=p.apkNativeLibs.resolve(filename);
            if(Files.isSymbolicLink(file) ||
                    !Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) ||
                    !Files.isReadable(file) || Files.size(file)<minimum ||
                    !file.toRealPath().startsWith(nativeHome)) return false;
            byte[] prefix=new byte[20];
            try(java.io.InputStream input=Files.newInputStream(file)) {
                if(input.read(prefix)!=prefix.length)return false;
            }
            return prefix[0]==0x7f && prefix[1]=='E' && prefix[2]=='L' &&
                    prefix[3]=='F' && prefix[4]==2 && prefix[5]==1 &&
                    (prefix[18]&0xff)==183 && (prefix[19]&0xff)==0;
        }catch(IOException e){return false;}
    }

    public static boolean ready(RuntimeLayout p) {
        // Original Wine elf and full FEX runtime are validated separately by
        // RuntimeAssessment. Only additional signed libraries are tested here.
        return trustedElf(p,"libwine_win32u.so",100000)
                && trustedElf(p,"librm11_win32u_fontclient.so",100000)
                && trustedElf(p,"librm11_ft.so",100000)
                && trustedElf(p,"librm11_wine_data_redirect.so",1000)
                && !Files.exists(p.apkNativeLibs.resolve("libfreetype.so"),
                        LinkOption.NOFOLLOW_LINKS);
    }

    public static String diagnostic(RuntimeLayout p) {
        return "RM11_V406_ISOLATED_WINEFILE_FONTCLIENT="
                +(ready(p)?"SIGNED_NATIVE_LIBS_READY":"DISABLED_OR_MISSING")
                +"\nRM11_V406_GENERIC_FREETYPE_ALIAS_PROHIBITED\n"
                +"RM11_V406_WINESERVER_AND_EXPLORER_UNMODIFIED\n";
    }

    /** Attempt exactly once. Never activate on retry, console, or games. */
    public static boolean attempt(int zeroBasedAttempt,boolean androidGlyphReady,
                                  RuntimeLayout p) {
        return zeroBasedAttempt==0 && androidGlyphReady && ready(p);
    }
}
