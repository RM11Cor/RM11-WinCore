package com.rm11.autocore.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Owner of ONLY the native processes launched by a future RM11 engine session.
 *
 * This component does not implement Wine child re-exec or reap processes
 * forked internally by Wine. Linux waitpid() works only on one's own children.
 * It does drain each direct child's pipe, waits for exit on shutdown, and
 * prevents killing unrelated app processes discovered via /proc.
 *
 * No integration into legacy v4.0.89: that APK remains untouched.
 */
public final class EngineOwnedProcessSession implements AutoCloseable {
    private static final int MAX_LOG_BYTES=32_768;
    private static final int CHUNK_BYTES=4096;
    private static final long MAX_SHUTDOWN_MS=10_000L;

    public enum State { ACTIVE, STOPPING, CLOSED }

    public static final class OwnedProcess {
        private final Process process;
        private final Thread stdoutThread;
        private final ByteArrayOutputStream tail=new ByteArrayOutputStream(MAX_LOG_BYTES);
        private volatile boolean readerCompleted;

        private OwnedProcess(Process p,String label) {
            process=p;
            stdoutThread=new Thread(()->{
                try(InputStream in=p.getInputStream()){
                    byte[] b=new byte[CHUNK_BYTES];
                    int n;
                    while((n=in.read(b))!=-1)if(n>0) {
                        synchronized(tail){
                            if(n>=MAX_LOG_BYTES) {
                                tail.reset();
                                tail.write(b,n-MAX_LOG_BYTES,MAX_LOG_BYTES);
                            } else {
                                int overflow=tail.size()+n-MAX_LOG_BYTES;
                                if(overflow>0) {
                                    byte[] existing=tail.toByteArray();
                                    tail.reset();
                                    tail.write(existing,overflow,existing.length-overflow);
                                }
                                tail.write(b,0,n);
                            }
                        }
                    }
                }catch(IOException ignored) {
                    // A dying guest closes its pipe; no panic/relaunch.
                }finally{readerCompleted=true;}
            },"rm11-engine-owned-"+label);
            stdoutThread.setDaemon(true);
            stdoutThread.start();
        }
        public boolean alive(){return process.isAlive();}
        public boolean readerFinished(){return readerCompleted;}
        public String outputTail(){
            synchronized(tail){
                return new String(tail.toByteArray(),java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        public Integer exitCodeIfFinished(){
            if(process.isAlive())return null;
            try{return process.exitValue();}
            catch(IllegalThreadStateException stillAlive){return null;}
        }
    }

    private final List<OwnedProcess> owned=new ArrayList<>();
    private State state=State.ACTIVE;

    public synchronized State state(){return state;}
    public synchronized int launchedCount(){return owned.size();}
    public synchronized List<OwnedProcess> processes(){
        return Collections.unmodifiableList(new ArrayList<>(owned));
    }

    /**
     * Only APK-native-library entrypoints may be launched on modern Android.
     * The signed APK must supply the actual binary, not writable ImageFs data.
     * The expected digest comes from the signed engine manifest and must not
     * be derived from user-provided game directories.
     */
    public synchronized OwnedProcess startSignedNative(Path apkLibDirectory,
           String libraryName,List<String> arguments,Path workingDirectory,
           Map<String,String> environment,String expectedSha256)throws IOException {
        if(state!=State.ACTIVE)throw new IOException("ENGINE_SESSION_NOT_ACTIVE");
        if(!("libwineprobe.so".equals(libraryName)
                ||"libwineserverrm11.so".equals(libraryName)
                ||"librm11_engine_supervisor.so".equals(libraryName)))
            throw new IOException("ENGINE_ENTRYPOINT_NOT_ALLOWLISTED");
        if(apkLibDirectory==null||workingDirectory==null
                ||arguments==null||environment==null
                ||expectedSha256==null)
            throw new IOException("ENGINE_LAUNCH_ARGUMENTS_MISSING");
        Path root=apkLibDirectory.toRealPath();
        Path target=root.resolve(libraryName);
        if(!Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS)
                ||Files.isSymbolicLink(target)||!Files.isExecutable(target))
            throw new IOException("ENGINE_SIGNED_NATIVE_ENTRYPOINT_MISSING");
        if(!expectedSha256.equals(EngineDataStager.sha256(target)))
            throw new IOException("ENGINE_NATIVE_ENTRYPOINT_HASH_MISMATCH");
        if(!Files.isDirectory(workingDirectory,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("ENGINE_WORKDIR_NOT_DIRECTORY");
        List<String> command=new ArrayList<>();
        command.add(target.toString());
        for(String arg:arguments){
            if(arg==null||arg.indexOf('\0')>=0)
                throw new IOException("ENGINE_UNSAFE_ARGUMENT");
            command.add(arg);
        }
        ProcessBuilder builder=new ProcessBuilder(command);
        builder.directory(workingDirectory.toFile());
        // Never inherit shell-injected LD_PRELOAD or Wine env from host.
        builder.environment().clear();
        for(Map.Entry<String,String> item:environment.entrySet()) {
            if(item.getKey()==null||item.getValue()==null
                    ||item.getKey().indexOf('=')>=0
                    ||item.getKey().indexOf('\0')>=0
                    ||item.getValue().indexOf('\0')>=0)
                throw new IOException("ENGINE_INVALID_ENVIRONMENT");
            builder.environment().put(item.getKey(),item.getValue());
        }
        builder.redirectErrorStream(true);
        return startProcessBuilder(builder,libraryName);
    }

    /**
     * One owner chain: Android Java -> APK-native supervisor ->
     * APK-native Wine -> its Wine child processes.
     *
     * Both SHA-256 values MUST come from the same trusted signed APK manifest.
     * The Android caller MUST pass ApplicationInfo.nativeLibraryDir, not an
     * arbitrary app-writable directory. This method is intentionally not
     * connected to the legacy Wine path until an APK/device integrity gate
     * and graphics proof exist.
     */
    public synchronized OwnedProcess startSupervisedWine(
            Path nativeLibraryDir,List<String> wineArguments,
            Path workingDirectory,Map<String,String> wineEnvironment,
            String expectedSupervisorSha256,String expectedWineLoaderSha256)
            throws IOException {
        if(state!=State.ACTIVE)throw new IOException("ENGINE_SESSION_NOT_ACTIVE");
        if(nativeLibraryDir==null || wineArguments==null ||
                workingDirectory==null || wineEnvironment==null)
            throw new IOException("ENGINE_SUPERVISOR_ARGUMENTS_MISSING");
        if(!Files.isDirectory(nativeLibraryDir,LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(nativeLibraryDir))
            throw new IOException("ENGINE_SUPERVISOR_NATIVE_LIBDIR_UNTRUSTED");
        Path root=nativeLibraryDir.toRealPath();
        Path wine=root.resolve("libwineprobe.so");
        if(!Files.isRegularFile(wine,LinkOption.NOFOLLOW_LINKS) ||
                Files.isSymbolicLink(wine) || !Files.isExecutable(wine))
            throw new IOException("ENGINE_WINE_ENTRYPOINT_UNAVAILABLE");
        if(expectedWineLoaderSha256==null ||
                !expectedWineLoaderSha256.matches("[0-9a-f]{64}") ||
                !expectedWineLoaderSha256.equals(EngineDataStager.sha256(wine)))
            throw new IOException("ENGINE_WINE_LOADER_HASH_MISMATCH");
        java.util.ArrayList<String> args=new java.util.ArrayList<>();
        args.add(wine.toString());
        args.addAll(wineArguments);
        java.util.HashMap<String,String> env=new java.util.HashMap<>(wineEnvironment);
        // The Java ProcessBuilder launches the supervisor, not Wine.
        // Dynamic-linker control variables apply BEFORE main(), so passing
        // the Wine LD_PRELOAD interposer directly would poison the reaper.
        if(env.containsKey("RM11_ENGINE_CHILD_LD_PRELOAD") ||
                env.containsKey("RM11_ENGINE_CHILD_LD_LIBRARY_PATH"))
            throw new IOException("ENGINE_RESERVED_CHILD_ENV_OVERRIDE");
        if(env.containsKey("LD_AUDIT") || env.containsKey("LD_DEBUG"))
            throw new IOException("ENGINE_SUPERVISOR_UNSAFE_LINKER_ENVIRONMENT");
        String guestPreload=env.remove("LD_PRELOAD");
        String guestLibPath=env.remove("LD_LIBRARY_PATH");
        if(guestPreload!=null)
            env.put("RM11_ENGINE_CHILD_LD_PRELOAD",guestPreload);
        if(guestLibPath!=null)
            env.put("RM11_ENGINE_CHILD_LD_LIBRARY_PATH",guestLibPath);
        String previous=env.put("RM11_ENGINE_APK_LIB_DIR",root.toString());
        if(previous!=null && !root.toString().equals(previous))
            throw new IOException("ENGINE_NATIVE_DIR_OVERRIDE_REJECTED");
        return startSignedNative(root,"librm11_engine_supervisor.so",
                args,workingDirectory,env,expectedSupervisorSha256);
    }

    // Visible only to the independent host-only test in same package.
    synchronized OwnedProcess startHostTestProcess(ProcessBuilder builder)
            throws IOException {
        if(state!=State.ACTIVE)throw new IOException("ENGINE_SESSION_NOT_ACTIVE");
        builder.redirectErrorStream(true);
        return startProcessBuilder(builder,"host-test");
    }

    private OwnedProcess startProcessBuilder(ProcessBuilder builder,String label)
            throws IOException {
        // Callers hold session lock: close() cannot race after the state check.
        Process p=builder.start();
        boolean inserted=false;
        try {
            OwnedProcess child=new OwnedProcess(p,label);
            owned.add(child);
            inserted=true;
            return child;
        }finally {
            if(!inserted) {
                p.destroyForcibly();
                try{p.waitFor(1000,TimeUnit.MILLISECONDS);}
                catch(InterruptedException stop){Thread.currentThread().interrupt();}
            }
        }
    }

    public synchronized void stopAll(long maxWaitMs)throws InterruptedException {
        if(state==State.CLOSED)return;
        state=State.STOPPING;
        long grace=Math.min(MAX_SHUTDOWN_MS,Math.max(0,maxWaitMs));
        // A single monotonic deadline is shared by all owned subprocesses.
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(grace);
        boolean interrupted=false;
        try{
            // First request a normal exit of EVERY direct child, not one at
            // a time (otherwise a later process gets no grace).
            for(OwnedProcess child:owned)if(child.process.isAlive())
                child.process.destroy();
            for(OwnedProcess child:owned){
                Process p=child.process;
                if(!p.isAlive())continue;
                long remaining=deadline-System.nanoTime();
                if(remaining>0) {
                    long ms=Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining));
                    p.waitFor(ms,TimeUnit.MILLISECONDS);
                }
            }
        }catch(InterruptedException ie) {
            interrupted=true;
        }finally {
            // Direct children only: never /proc-kill 94 possibly unrelated
            // Wine PIDs and never signal an unverified PID.
            for(OwnedProcess child:owned)if(child.process.isAlive())
                child.process.destroyForcibly();
            for(OwnedProcess child:owned){
                try {
                    child.process.waitFor(2000,TimeUnit.MILLISECONDS);
                    child.stdoutThread.join(100);
                }catch(InterruptedException ie) {
                    interrupted=true;
                }
            }
            state=State.CLOSED;
        }
        if(interrupted) {
            Thread.currentThread().interrupt();
            throw new InterruptedException("ENGINE_SESSION_CLEANUP_INTERRUPTED");
        }
    }

    @Override public void close(){
        try{stopAll(1500);}
        catch(InterruptedException stop){Thread.currentThread().interrupt();}
    }
}
