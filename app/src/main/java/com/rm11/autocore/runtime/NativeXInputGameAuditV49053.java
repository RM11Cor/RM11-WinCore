package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.RM11VirtualXInputV49037;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Per-launch, read-only proof of which XInput DLL the *selected game's Wine
 * process* actually loads, plus native GetState/Capabilities read deltas.
 * This does NOT inject input, change game files, alter controller mappings,
 * or mistake the already-successful standalone probe for game recognition.
 */
public final class NativeXInputGameAuditV49053 {
    private static final Pattern WINE_DLL=Pattern.compile(
        "(?i)Loaded\\s+L\\\"([^\\\"\\r\\n]*xinput(?:1_4|1_3|9_1_0)\\.dll)\\\"[^\\r\\n]*?(native|builtin)");
    private static final int MAX_CARRY=1024;
    private final Context app;
    private final String game;
    private final Path state;
    private final int baselineState,baselineCapabilities;
    private String carry="";
    private String provider="NOT_SEEN_IN_WINE_LOG";
    private boolean appLocalLoaded=false;
    private boolean wineBuiltinLoaded=false;
    private int matchingDllEvents=0;

    private static int[] counters(Path path){
        try {
            if(Files.isSymbolicLink(path)
                    ||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)
                    ||Files.size(path)!=64)return new int[]{-1,-1};
            byte[] data=Files.readAllBytes(path);
            ByteBuffer memory=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            if(memory.getInt(0)!=0x524d3131 || memory.getInt(4)!=1)
                return new int[]{-1,-1};
            return new int[]{memory.getInt(32),memory.getInt(36)};
        }catch(Exception ignored){return new int[]{-1,-1};}
    }

    public NativeXInputGameAuditV49053(Context context,Path gameExe){
        app=context.getApplicationContext();
        game=gameExe.getFileName().toString();
        state=RM11VirtualXInputV49037.statePath(context);
        int[] initial=counters(state);
        baselineState=initial[0];
        baselineCapabilities=initial[1];
        record("BEFORE_GAME_LAUNCH");
    }

    public synchronized void observe(String chunk){
        if(chunk==null||chunk.isEmpty())return;
        String joined=carry+chunk;
        Matcher m=WINE_DLL.matcher(joined);
        while(m.find()){
            String loaded=m.group(1).toLowerCase(Locale.ROOT);
            String kind=m.group(2).toLowerCase(Locale.ROOT);
            boolean privateDll=loaded.contains("rm11-xinput-app-local-v49051-")
                    ||loaded.contains("carx-app-local-v49034");
            if(privateDll && "native".equals(kind))appLocalLoaded=true;
            if("builtin".equals(kind))wineBuiltinLoaded=true;
            if(matchingDllEvents<50)matchingDllEvents++;
            provider=privateDll?"APP_PRIVATE_"+kind.toUpperCase(Locale.ROOT)
                    :"OTHER_"+kind.toUpperCase(Locale.ROOT);
        }
        carry=joined.substring(Math.max(0,joined.length()-MAX_CARRY));
    }

    public synchronized void record(String phase){
        int[] now=counters(state);
        int reads=baselineState>=0 && now[0]>=baselineState
                ?now[0]-baselineState:-1;
        int caps=baselineCapabilities>=0 && now[1]>=baselineCapabilities
                ?now[1]-baselineCapabilities:-1;
        String status;
        if(appLocalLoaded && reads>0)status="APP_LOCAL_XINPUT_POLLS_OBSERVED_DURING_GAME_SESSION";
        else if(reads>0)status="XINPUT_POLLS_WITHOUT_CONFIRMED_APP_LOCAL_DLL";
        else if(appLocalLoaded)status="APP_LOCAL_XINPUT_DLL_LOADED_BUT_NOT_POLLED";
        else if(wineBuiltinLoaded)status="WINE_BUILTIN_XINPUT_LOADED";
        else status="NO_XINPUT_DLL_LOAD_OR_POLL_OBSERVED";
        OfflineDiagnosticJournal.record(app,"v49053-game-xinput-audit",
                "RM11_V49053_GAME_EXE="+game+"\n"
                +"RM11_V49053_PHASE="+phase+"\n"
                +"RM11_V49053_EFFECTIVE_DLL_PROVIDER="+provider+"\n"
                +"RM11_V49053_APP_LOCAL_XINPUT_LOADED="+appLocalLoaded+"\n"
                +"RM11_V49053_WINE_BUILTIN_XINPUT_LOADED="+wineBuiltinLoaded+"\n"
                +"RM11_V49053_XINPUT_DLL_LOAD_EVENTS="+matchingDllEvents+"\n"
                +"RM11_V49053_GETSTATE_DELTA="+reads+"\n"
                +"RM11_V49053_GETCAPABILITIES_DELTA="+caps+"\n"
                +"RM11_V49053_INPUT_ROUTE_ASSESSMENT="+status+"\n"
                +"RM11_V49053_GAME_ACK=NOT_INFERRED_FROM_DLL_LOAD_ONLY");
    }
}
