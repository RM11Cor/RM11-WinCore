package com.rm11.autocore.runtime;

import android.content.Context;
import android.os.SystemClock;
import com.rm11.autocore.diagnostics.DiagnosticSanitizer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;

/**
 * A separate live, bounded, app-private diagnostic stream for real Windows
 * games. Existing rolling journals kept only a short Wine tail, so the first
 * actual game-side error could disappear long before a ZIP was exported.
 *
 * No files in the selected game directory are opened, written or changed.
 * This deliberately does not change Wine, FEX, VKD3D, X11 or XInput flags.
 */
public final class GameWineSignalJournalV49113 {
    public static final String FILE="last-v49113-live-game-signals.log";
    private static final long MAX_BYTES=160000L;
    private static final int MAX_LINES=700;
    private final Path target;
    private final long started=SystemClock.elapsedRealtime();
    private final StringBuilder incomplete=new StringBuilder();
    private int lines;
    private long written;
    private boolean stopped;
    private GameWineSignalJournalV49113(Path target,long written){
        this.target=target;this.written=written;
    }
    public static GameWineSignalJournalV49113 begin(Context ctx,String exeName){
        if(ctx==null)return null;
        try{
            Path dir=ctx.getFilesDir().toPath().resolve("offline-diagnostics");
            Files.createDirectories(dir);
            Path file=dir.resolve(FILE);
            if(Files.isSymbolicLink(file))return null;
            String name=exeName==null?"UNKNOWN":
                exeName.replaceAll("[^A-Za-z0-9_. -]","_");
            if(name.length()>80)name=name.substring(0,80);
            String header="KERNIX_V49113_LIVE_GAME_WINE_SIGNALS=ACTIVE\n"
                +"KERNIX_V49113_EXE_BASENAME="+name+"\n"
                +"KERNIX_V49113_GAME_FRAME_VERIFIED=false\n";
            byte[] initial=header.getBytes(StandardCharsets.UTF_8);
            Files.write(file,initial,StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE);
            return new GameWineSignalJournalV49113(file,initial.length);
        }catch(Exception ignored){return null;}
    }
    /** Relevant diagnostics only: skip the large SEH/unwind and X11 trace
     * spam that previously evicted the first useful game messages. */
    public static boolean important(String value){
        if(value==null||value.isEmpty())return false;
        String s=value.toLowerCase(Locale.ROOT);
        if(s.contains("err:")||s.contains("fatal")||s.contains("failed")
             ||s.contains("exception code=c000")||s.contains("device lost")
             ||s.contains("vk_error")||s.contains("dxgi_error")
             ||s.contains("x connection to")||s.contains("not implemented")
             ||s.contains("unhandled exception"))return true;
        if(s.contains("warn:")&&!s.contains("trace:unwind"))return true;
        if(s.contains("streamline")&&
                (s.contains("d3d12")||s.contains("dxgi")))return true;
        if(s.contains("vkd3d-proton")&&
                (s.contains("device")||s.contains("swapchain")
                  ||s.contains("present")||s.contains("shader model")
                  ||s.contains("adapter")))return true;
        if(s.contains("loaded ")&&
                (s.contains("witcher3.exe")||s.contains("d3d12.dll")
                  ||s.contains("dxgi.dll")))return true;
        return false;
    }
    private void appendSignal(String line){
        if(stopped||!important(line))return;
        if(lines>=MAX_LINES||written>=MAX_BYTES){
            stopped=true;
            return;
        }
        String safe=DiagnosticSanitizer.scrub(line,1200);
        String item="T+"+(SystemClock.elapsedRealtime()-started)
            +"ms "+safe+"\n";
        byte[] bytes=item.getBytes(StandardCharsets.UTF_8);
        if(written+bytes.length>MAX_BYTES){stopped=true;return;}
        try{
            Files.write(target,bytes,StandardOpenOption.APPEND);
            written+=bytes.length;
            lines++;
        }catch(Exception ignored){stopped=true;}
    }
    public synchronized void accept(String chunk){
        if(stopped||chunk==null||chunk.isEmpty())return;
        incomplete.append(chunk);
        int end;
        while((end=incomplete.indexOf("\n"))>=0){
            String line=incomplete.substring(0,end);
            incomplete.delete(0,end+1);
            appendSignal(line);
            if(stopped)break;
        }
        if(incomplete.length()>8192)
            incomplete.delete(0,incomplete.length()-4096);
    }
    public synchronized void finish(){
        if(incomplete.length()>0){
            appendSignal(incomplete.toString());
            incomplete.setLength(0);
        }
    }
}
