package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.RM11VirtualXInputV49037;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

/** Opt-in, isolated verification of the REAL Winebus/SDL2 device path.
 *  Neither the normal game nor the existing Wine prefix controllers are changed.
 *  A staged EXE tests Windows DirectInput enumeration alongside XInput calls.
 */
public final class VPadBusProbeV49044 {
    public static final String EXE="RM11-VPAD-WINEBUS-PROBE.exe";
    private static final String ASSET="rm11-v49044-controller/"+EXE;
    private VPadBusProbeV49044(){}

    public static Path installProbe(Context context,RuntimeLayout layout)throws IOException {
        Path c=layout.winePrefix.resolve("drive_c").toRealPath();
        if(!Files.isDirectory(c,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Wine C: isn't ready");
        Path folder=c.resolve("RM11-Controller-Tests");
        if(Files.isSymbolicLink(folder))throw new IOException("Untrusted probe directory");
        Files.createDirectories(folder);
        Path destination=folder.resolve(EXE);
        if(Files.isSymbolicLink(destination))throw new IOException("Untrusted probe EXE");
        Path tmp=folder.resolve(EXE+".tmp");
        if(Files.isSymbolicLink(tmp))throw new IOException("Untrusted temporary EXE");
        try(InputStream in=context.getAssets().open(ASSET);
            OutputStream out=Files.newOutputStream(tmp)){
            byte[] bytes=new byte[32768];
            for(int n;(n=in.read(bytes))!=-1;)out.write(bytes,0,n);
        }
        if(Files.size(tmp)<4096)throw new IOException("Incomplete signed probe EXE");
        try{
            Files.move(tmp,destination,StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        }catch(java.nio.file.AtomicMoveNotSupportedException ignored){
            Files.move(tmp,destination,StandardCopyOption.REPLACE_EXISTING);
        }
        OfflineDiagnosticJournal.record(context,"v49044-winebus-probe",
            "RM11_V49044_SIGNED_WIN64_PROBE_STAGED=true\n"
            +"RM11_V49044_TARGET="+destination.getFileName()+"\n"
            +"RM11_V49044_REQUIRES_NATIVE_DI_ENUM_EVIDENCE=true");
        return destination;
    }
    public static boolean isProbe(Path path){
        return path!=null&&EXE.equalsIgnoreCase(path.getFileName().toString());
    }
    /** Launch-time SDL bridge injection into the Wine desktop bootstrap.
     *  Its ELF constructor is guarded to only run in Wine's service process.
     *  This is an attempt to place a virtual controller in the Winebus SDL
     *  address space. The in-game DirectInput enumeration remains unverified.
     */
    public static java.util.Map<String,String> wineServiceEnvironment(
            Context context,RuntimeLayout layout,
            java.util.Map<String,String> original){
        java.util.Map<String,String> overrides=new java.util.LinkedHashMap<>();
        Path nativeBridge=layout.apkNativeLibs.resolve("librm11_vpad_sdl_bus_bridge.so");
        if(!Files.isRegularFile(nativeBridge,LinkOption.NOFOLLOW_LINKS)){
            OfflineDiagnosticJournal.record(context,"v49045-winebus-session",
                "RM11_V49045_NATIVE_BRIDGE_NOT_PACKAGED=true");
            return overrides;
        }
        Path diagnostic=layout.appFiles.resolve("offline-diagnostics");
        try{
            Files.createDirectories(diagnostic);
            // Remove old service evidence before every attempt. A log from
            // v49045 must not be mistaken for v49047 native recognition.
            Files.deleteIfExists(diagnostic.resolve("last-v49045-wine-service-pad.log"));
            // The v49045 device diagnostics proved Wine's service constructor ran
            // but could not find libSDL2-2.0.so.0. Ship the SDL2 dependency as a
            // signed APK native library, and expose Wine's exact SONAME via a
            // symlink in the private runtime's existing loader search path.
            Path sdl=layout.apkNativeLibs.resolve("libSDL2.so");
            if(!Files.isRegularFile(sdl,LinkOption.NOFOLLOW_LINKS)){
                OfflineDiagnosticJournal.record(context,"v49046-sdl-dependency",
                    "RM11_V49046_NATIVE_SDL2_MISSING_IN_SIGNED_APK=true");
                return overrides;
            }
            // v49048 root-cause fix: our actual Wine image has NO imagefs/usr/lib.
            // v49046/v49047 checked that non-existent location and always
            // skipped the entire controller bus bootstrap. Use a known
            // app-owned native alias directory, not an imagined imagefs path.
            Path lib=layout.appFiles.resolve("rm11-controller-native-libs");
            Path trusted=layout.appFiles.toRealPath();
            if(Files.isSymbolicLink(lib)){
                OfflineDiagnosticJournal.record(context,"v49048-winedevice-bus",
                    "RM11_V49048_NATIVE_ALIAS_DIRECTORY_SYMLINK_REFUSED");
                return overrides;
            }
            if(!Files.exists(lib,LinkOption.NOFOLLOW_LINKS))
                Files.createDirectory(lib);
            if(!Files.isDirectory(lib,LinkOption.NOFOLLOW_LINKS)
                    || !lib.toRealPath().startsWith(trusted)){
                OfflineDiagnosticJournal.record(context,"v49048-winedevice-bus",
                    "RM11_V49048_NATIVE_ALIAS_DIRECTORY_UNSAFE");
                return overrides;
            }
            for(String soname:new String[]{"libSDL2-2.0.so.0","libSDL2-2.0.so"}){
                Path alias=lib.resolve(soname);
                if(Files.isSymbolicLink(alias)){
                    Path previous=Files.readSymbolicLink(alias);
                    if(!previous.equals(sdl)){
                        // After an APK update, Android may move the signed SDL
                        // library to a new package-install path. The old
                        // app-private alias is stale and must be refreshed.
                        if(!previous.isAbsolute()
                                || !previous.getFileName().toString().equals("libSDL2.so")
                                || !previous.toString().contains("/lib/arm64/"))
                            throw new IOException("SDL2_SONAME_UNTRUSTED_COLLISION");
                        Files.delete(alias);
                        Files.createSymbolicLink(alias,sdl);
                        OfflineDiagnosticJournal.record(context,"v49045-winebus-session",
                            "RM11_V49050_STALE_SDL_SONAME_REBOUND_TO_CURRENT_APK=true");
                    }
                }else if(Files.exists(alias,LinkOption.NOFOLLOW_LINKS)){
                    throw new IOException("SDL2_SONAME_FILE_COLLISION");
                }else{
                    Files.createSymbolicLink(alias,sdl);
                }
            }
            overrides.put("RM11_V49046_SDL2_ABSOLUTE",sdl.toString());
            OfflineDiagnosticJournal.record(context,"v49048-winedevice-bus",
                "RM11_V49048_SDL_ALIAS_DIRECTORY_CREATED=true\\n"
                +"RM11_V49048_SDL2_CANONICAL_LIBRARY_PRESENT=true\\n"
                +"RM11_V49048_EXPECTED_PROCESS=winedevice.exe\\n"
                +"RM11_V49048_BUS_GAME_CONTROLLER_ENUMERATION=PENDING_ON_DEVICE");
            OfflineDiagnosticJournal.record(context,"v49046-sdl-dependency",
                "RM11_V49046_SIGNED_SDL2_NATIVE_LIB_PRESENT=true\\n"
                +"RM11_V49046_WINE_SDL_SONAME_ALIAS=PRIVATE_RUNTIME_LINKS_CREATED\\n"
                +"RM11_V49046_WINEBUS_ENUMERATION=NOT_YET_PROVEN");
            Path status=diagnostic.resolve("last-v49045-wine-service-pad.log");
            Files.deleteIfExists(status);
            String previous=original.get("LD_PRELOAD");
            overrides.put("LD_PRELOAD",nativeBridge.toString()+
                (previous==null||previous.isEmpty()?"":" "+previous));
            overrides.put("RM11_V49044_BUS_ENABLE","1");
            overrides.put("RM11_V49045_REQUIRE_WINEBUS_HOST","1");
            overrides.put("RM11_V49044_STATE_UNIXPATH",
                RM11VirtualXInputV49037.statePath(context).toString());
            overrides.put("RM11_V49044_STATUS_UNIXPATH",status.toString());
            // Bionic Wine may launch services through an ELF redirector; this
            // native lib directory is on the host's preexisting library path.
            String libraryPath=original.get("LD_LIBRARY_PATH");
            overrides.put("LD_LIBRARY_PATH",lib.toString()+":"+
                layout.apkNativeLibs.toString()+
                (libraryPath==null||libraryPath.isEmpty()?"":":"+libraryPath));
            // These variables are inherited by Wine services only if their
            // parent Wine loader propagates LD_PRELOAD; runtime log proves it.
            OfflineDiagnosticJournal.record(context,"v49045-winebus-session",
                "RM11_V49045_ANDROID_TOUCH_SOURCE=SHARED_XINPUT_MMAP\\n"
                +"RM11_V49045_WINE_SERVICE_PRELOAD=REQUESTED\\n"
                +"RM11_V49045_GAME_NATIVE_ENUMERATION=NOT_VERIFIED\\n"
                +"RM11_V49045_NO_ROOT_OR_UINPUT=true");
            return overrides;
        }catch(IOException error){
            OfflineDiagnosticJournal.record(context,"v49045-winebus-session",
                "RM11_V49045_PRELOAD_SETUP_FAILED="+error.getClass().getSimpleName()+"\\n"
                +"RM11_V49050_SERVICE_SETUP_CAUSE="+
                 ("SDL2_SONAME_UNTRUSTED_COLLISION".equals(error.getMessage())
                   ?"UNTRUSTED_SDL_SONAME":"IO_FAILURE"));
            return new java.util.LinkedHashMap<>();
        }
    }

    /**
     * v49054: Let Winebus call SDL_Init() itself. The signed SDL2 library now
     * creates the virtual joystick on that SAME call/instance, after genuine
     * SDL initialization. We never preload the old ELF worker, whose separate
     * SDL_InitSubSystem call hung in previous device reports.
     */
    public static java.util.Map<String,String> nativeWinebusEnvironmentV49054(
            Context context,RuntimeLayout layout,
            java.util.Map<String,String> original){
        java.util.Map<String,String> nativeEnv=
                wineServiceEnvironment(context,layout,original);
        // Existing helper safely exposes the installed SDL SONAME aliases and
        // app-private library location. Remove its EXPERIMENTAL preload.
        if(!nativeEnv.containsKey("RM11_V49046_SDL2_ABSOLUTE")
                ||!nativeEnv.containsKey("LD_LIBRARY_PATH")){
            OfflineDiagnosticJournal.record(context,"v49054-winebus-activation",
                "RM11_V49054_CONTROLLER_BUS=NOT_READY_SDL_ALIAS_OR_NATIVE_LIB_MISSING");
            return new java.util.LinkedHashMap<>();
        }
        nativeEnv.remove("LD_PRELOAD");
        nativeEnv.remove("RM11_V49044_BUS_ENABLE");
        nativeEnv.remove("RM11_V49045_REQUIRE_WINEBUS_HOST");
        java.nio.file.Path status=layout.appFiles.resolve("offline-diagnostics")
                .resolve("last-v49054-sdl-winebus.log");
        try {
            java.nio.file.Files.deleteIfExists(status);
        } catch (IOException failure){
            OfflineDiagnosticJournal.record(context,"v49054-winebus-activation",
                "RM11_V49054_STATUS_LOG_RESET="+failure.getClass().getSimpleName());
        }
        nativeEnv.put("RM11_V49054_NATIVE_SDL_DEVICE","1");
        nativeEnv.put("RM11_V49054_STATUS_UNIXPATH",status.toString());
        OfflineDiagnosticJournal.record(context,"v49054-winebus-activation",
                "RM11_V49054_CONTROLLER_BUS=SDL_POST_INIT_IN_NATIVE_WINEBUS_REQUESTED\n"
                +"RM11_V49054_LEGACY_CONCURRENT_SDL_PRELOAD=DISABLED\n"
                +"RM11_V49054_INPUT_SHARED_MMAP="
                   +nativeEnv.containsKey("RM11_V49044_STATE_UNIXPATH")+"\n"
                +"RM11_V49054_WINE_HID_ENUMERATION=UNVERIFIED_UNTIL_DEVICE_LOG");
        return nativeEnv;
    }


    /**
     * v49057: Source-built native Wine HID bus. The Linux Winebus library is
     * *actually replaced* before server launch, and both the server and game
     * inherit the same native mmap and bounded diagnostics. If the installed
     * Wine base hash differs from the signed pinned base, do NOT enable the
     * new HID path. The old SDL/XInput route remains available as fallback.
     */
    public static java.util.Map<String,String> nativeWinebusEnvironmentV49057(
            Context context,RuntimeLayout layout,
            java.util.Map<String,String> original) {
        java.util.Map<String,String> env=
                nativeWinebusEnvironmentV49054(context,layout,original);
        boolean installed=NativeWineHidInstallerV49057.prepare(context,layout);
        boolean mmap=env.containsKey("RM11_V49044_STATE_UNIXPATH");
        Path log=layout.appFiles.resolve("offline-diagnostics")
                .resolve("last-v49057-native-winebus-hid.log");
        try {
            Files.createDirectories(log.getParent());
            Files.deleteIfExists(log);
        }catch(IOException error){
            OfflineDiagnosticJournal.record(context,"v49057-native-hid-activation",
                "RM11_V49057_NATIVE_HID_LOG_RESET="+error.getClass().getSimpleName());
        }
        if(installed && mmap) {
            env.put("RM11_NATIVE_HID_BUS","1");
            env.put("RM11_NATIVE_HID_STATUS_PATH",log.toString());
            // The Winebus sdl_init/sdl_wait Unix-call slots now implement
            // native PnP input. No SDL2 side-loaded virtual device is required.
            env.remove("RM11_V49054_NATIVE_SDL_DEVICE");
        } else {
            env.remove("RM11_NATIVE_HID_BUS");
            env.remove("RM11_NATIVE_HID_STATUS_PATH");
        }
        OfflineDiagnosticJournal.record(context,"v49057-native-hid-activation",
            "RM11_V49057_NATIVE_HID_WINEBUS_INSTALLED="+installed+"\n"
            +"RM11_V49057_MMAP_PRESENT="+mmap+"\n"
            +"RM11_V49057_NATIVE_BUS_ENABLED="+env.containsKey("RM11_NATIVE_HID_BUS")+"\n"
            +"RM11_V49057_NATIVE_WINEBUS_DEVICE_ENUMERATION=UNVERIFIED_ON_DEVICE");
        return env;
    }

    /** Preload only for the named diagnostic, not for real games or Wine desktop. */
    public static String prepare(Context context,RuntimeLayout layout,
                                 Path selected,Map<String,String> environment){
        if(!isProbe(selected))return "SKIPPED_NOT_PROBE";
        Path nativeBridge=layout.apkNativeLibs.resolve("librm11_vpad_sdl_bus_bridge.so");
        if(!Files.isRegularFile(nativeBridge,LinkOption.NOFOLLOW_LINKS))
            return "NATIVE_BRIDGE_MISSING_IN_APK";
        Path diagnostic=layout.appFiles.resolve("offline-diagnostics");
        try{
            Files.createDirectories(diagnostic);
            Path nativeLog=diagnostic.resolve("last-v49044-sdlbus-native.log");
            Path windowsLog=diagnostic.resolve("last-v49044-win-enumeration.log");
            Files.deleteIfExists(nativeLog);
            Files.deleteIfExists(windowsLog);
            // v49051 device result: native Wine probe exits 139 before any
            // Windows PE is executed while SDL is preloaded. Never LD_PRELOAD
            // the headless SDL bridge into the probe's Wine loader. The probe
            // is a regular Win64 EXE and queries our authenticated XInput DLL.
            environment.put("RM11_V49044_STATE_UNIXPATH",
                     RM11VirtualXInputV49037.statePath(context).toString());
            environment.remove("RM11_V49044_BUS_ENABLE");
            environment.remove("RM11_V49044_STATUS_UNIXPATH");
            environment.put("RM11_V49044_PROBE_WINPATH",
                     "Z:"+windowsLog.toString().replace('/','\\'));
            OfflineDiagnosticJournal.record(context,"v49044-winebus-probe",
                "RM11_V49052_NATIVE_SDL_BRIDGE=DISABLED_DIRECT_WIN32_XINPUT_PROBE\n"
                +"RM11_V49044_WINDOWS_ENUMERATION=UNVERIFIED\n"
                +"RM11_V49044_PROCESS_SCOPE=CONTROLLER_PROBE_ONLY");
            return "WIN32_XINPUT_PROBE_WITHOUT_SDL_PRELOAD";
        }catch(IOException error){
            return "PROBE_SETUP_FAILED_"+error.getClass().getSimpleName();
        }
    }
}
