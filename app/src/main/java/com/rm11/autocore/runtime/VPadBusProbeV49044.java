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
            String previous=environment.get("LD_PRELOAD");
            environment.put("LD_PRELOAD",nativeBridge.toString()
                 +(previous==null||previous.isEmpty()?"":" "+previous));
            environment.put("RM11_V49044_BUS_ENABLE","1");
            environment.put("RM11_V49044_STATE_UNIXPATH",
                     RM11VirtualXInputV49037.statePath(context).toString());
            environment.put("RM11_V49044_STATUS_UNIXPATH",nativeLog.toString());
            environment.put("RM11_V49044_PROBE_WINPATH",
                     "Z:"+windowsLog.toString().replace('/','\\'));
            OfflineDiagnosticJournal.record(context,"v49044-winebus-probe",
                "RM11_V49044_NATIVE_SDL_BRIDGE=DIAGNOSTIC_PRELOAD_REQUESTED\n"
                +"RM11_V49044_WINDOWS_ENUMERATION=UNVERIFIED\n"
                +"RM11_V49044_PROCESS_SCOPE=CONTROLLER_PROBE_ONLY");
            return "PROBE_PRELOAD_REQUESTED_NOT_ENUMERATION_PROOF";
        }catch(IOException error){
            return "PROBE_SETUP_FAILED_"+error.getClass().getSimpleName();
        }
    }
}
