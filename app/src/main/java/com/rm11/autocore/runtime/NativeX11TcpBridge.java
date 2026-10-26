package com.rm11.autocore.runtime;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

/**
 * v4 native-server transport: Wine's unchanged DISPLAY=127.0.0.1:2 speaks
 * TCP, but Termux X.Org expects $TMPDIR/.X11-unix/X2 (AF_UNIX).
 *
 * This tightly-scoped, loopback-only byte relay belongs exclusively to the
 * future native display session. It does NOT start the server, draw a frame,
 * turn a core-only Java server into X.Org, or prove visible Wine text.
 * Never start it concurrently with the old embedded XServer on TCP 6002.
 */
public final class NativeX11TcpBridge implements AutoCloseable {
    public static final int DISPLAY_NUMBER=2;
    public static final int TCP_PORT=6000+DISPLAY_NUMBER;
    // Wine/Hangover can open an X11 connection per GUI thread. A real
    // REDMAGIC game launch reached 24/24 clients and XOpenDisplay failed.
    // X.Org itself supports many more clients. Admit enough simultaneous
    // Wine clients while retaining an explicit relay resource bound.
    private static final int MAX_CLIENTS=96;
    private final Semaphore permits=new Semaphore(MAX_CLIENTS);
    private final Map<Socket,LocalSocket> sessions=new ConcurrentHashMap<>();
    private final AtomicLong clientCount=new AtomicLong();
    private final AtomicLong tcpAccepted=new AtomicLong();
    private final AtomicLong rejectedAtCapacity=new AtomicLong();
    private final AtomicLong peakConcurrentClients=new AtomicLong();
    private final AtomicLong unixConnectFailures=new AtomicLong();
    private final AtomicLong transportFailures=new AtomicLong();
    private final AtomicLong tcpEof=new AtomicLong();
    private final AtomicLong unixEof=new AtomicLong();
    private final AtomicLong bytesFromWine=new AtomicLong();
    private final AtomicLong bytesFromXorg=new AtomicLong();
    private final ExecutorService pool=Executors.newCachedThreadPool(r->{
        Thread t=new Thread(r,"rm11-v4-native-x11-relay");
        t.setDaemon(true);
        return t;
    });

    private volatile ServerSocket listener;
    private volatile File unixEndpoint;
    private volatile boolean stopped=true;

    public static File endpoint(File privateTmp,int display) throws IOException {
        if(privateTmp==null || display<0 || display>99)
            throw new IOException("RM11_V4_INVALID_X11_UNIX_TMPDIR_OR_DISPLAY");
        File root=privateTmp.getCanonicalFile();
        if(!root.isDirectory() || !root.canRead())
            throw new IOException("RM11_V4_NATIVE_X11_TMPDIR_NOT_READY");
        File path=new File(new File(root,".X11-unix"),"X"+display);
        if(path.getAbsolutePath().getBytes(StandardCharsets.UTF_8).length>=100)
            throw new IOException("RM11_V4_UNIX_SOCKET_PATH_TOO_LONG");
        return path;
    }

    public synchronized void start(File privateTmp) throws IOException {
        if(!stopped)throw new IOException("RM11_V4_RELAY_ALREADY_RUNNING");
        if(pool.isShutdown())throw new IOException("RM11_V4_RELAY_ALREADY_CLOSED");
        File path=endpoint(privateTmp,DISPLAY_NUMBER);
        ServerSocket sock=new ServerSocket();
        sock.setReuseAddress(true);
        // No 0.0.0.0 listener. Wine connects only from same Android device.
        sock.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),TCP_PORT),128);
        sock.setSoTimeout(600);
        unixEndpoint=path;
        listener=sock;
        stopped=false;
        pool.execute(this::acceptLoop);
    }

    private void acceptLoop() {
        while(!stopped) {
            Socket tcp=null;
            try {
                ServerSocket server=listener;
                if(server==null)break;
                tcp=server.accept();
                tcpAccepted.incrementAndGet();
                tcp.setTcpNoDelay(true);
                if(!permits.tryAcquire()) {
                    rejectedAtCapacity.incrementAndGet();
                    closeQuietly(tcp);
                    continue;
                }
                // Track admitted slots, including accepted sockets that have
                // not yet connected to X.Org. The prior sessions.size()
                // obscured pending-but-already-permitted clients.
                peakConcurrentClients.accumulateAndGet(
                        MAX_CLIENTS-permits.availablePermits(),Math::max);
                Socket accepted=tcp;
                try {
                    pool.execute(()->relay(accepted));
                } catch(RuntimeException schedulingFailed) {
                    permits.release();
                    throw schedulingFailed;
                }
            } catch(SocketTimeoutException idle) {
                // Poll stop flag without binding the Android lifecycle.
            } catch(IOException e) {
                // Error after accept() must not leave an untracked socket open.
                closeQuietly(tcp);
                if(!stopped)android.util.Log.w("RM11-NativeX11","relay accept: "+e);
            } catch(RuntimeException e) {
                if(tcp!=null)closeQuietly(tcp);
                if(!stopped)android.util.Log.e("RM11-NativeX11","relay lifecycle error",e);
            }
        }
    }

    private void relay(Socket tcp) {
        LocalSocket unix=new LocalSocket();
        sessions.put(tcp,unix);
        try {
            // Connect only to Termux X.Org's verified app-private Unix path.
            // The native server is separately responsible for creating it.
            unix.connect(new LocalSocketAddress(unixEndpoint.getAbsolutePath(),
                    LocalSocketAddress.Namespace.FILESYSTEM));
            clientCount.incrementAndGet();
            Thread outgoing=new Thread(()->{
                try {
                    pump(tcp.getInputStream(),unix.getOutputStream(),bytesFromWine);
                    tcpEof.incrementAndGet();
                } catch(IOException failure) {
                    transportFailures.incrementAndGet();
                    // Other direction or service shutdown closes this pair.
                } finally {
                    closeQuietly(tcp);
                    closeQuietly(unix);
                }
            },"rm11-v4-x11-upstream");
            outgoing.setDaemon(true);
            outgoing.start();
            pump(unix.getInputStream(),tcp.getOutputStream(),bytesFromXorg);
            unixEof.incrementAndGet();
        } catch(IOException e) {
            transportFailures.incrementAndGet();
            if(!stopped && !unix.isConnected())unixConnectFailures.incrementAndGet();
            if(!stopped)android.util.Log.w("RM11-NativeX11","native Unix X11 not ready: "+e);
        } finally {
            closeQuietly(unix);
            closeQuietly(tcp);
            sessions.remove(tcp);
            permits.release();
        }
    }

    private static void pump(InputStream in,OutputStream out,AtomicLong tally)
            throws IOException {
        byte[] buffer=new byte[32768];
        int n;
        while((n=in.read(buffer))!=-1) {
            out.write(buffer,0,n);
            tally.addAndGet(n);
        }
    }

    public String diagnostics() {
        File target=unixEndpoint;
        return "RM11_V4_NATIVE_X11_TCP_UNIX_RELAY\n"
                +"listen: 127.0.0.1:"+TCP_PORT+"\n"
                +"legacy Java server conflict: NOT_VERIFIED; caller must own port exclusively\n"
                +"Unix endpoint: "+(target==null?"UNCONFIGURED":target.getAbsolutePath())+"\n"
                +"Unix socket exists: "+(target!=null && target.exists())+"\n"
                +"active TCP clients: "+sessions.size()+"\n"
                +"RM11_V459_RELAY_MAX_CLIENTS="+MAX_CLIENTS+"\n"
                +"RM11_V459_RELAY_RESERVED_CLIENTS="
                    +(MAX_CLIENTS-permits.availablePermits())+"\n"
                +"RM11_V459_RELAY_PEAK_CLIENTS="+peakConcurrentClients.get()+"\n"
                +"RM11_V459_RELAY_REJECTED_CLIENTS="+rejectedAtCapacity.get()+"\n"
                +"RM11_V459_RELAY_CAPACITY_EXHAUSTED="
                    +(rejectedAtCapacity.get()>0)+"\n"
                +"accepted native X11 clients: "+clientCount.get()+"\n"
                +"tcp accepted total: "+tcpAccepted.get()+"\n"
                +"unix connect failures: "+unixConnectFailures.get()+"\n"
                +"relay transport IO failures: "+transportFailures.get()+"\n"
                +"TCP client EOF closures: "+tcpEof.get()+"\n"
                +"native Xorg EOF closures: "+unixEof.get()+"\n"
                +"bytes Wine-to-X.Org: "+bytesFromWine.get()+"\n"
                +"bytes X.Org-to-Wine: "+bytesFromXorg.get()+"\n"
                +"native X.Org render and Wine text: NOT VERIFIED\n";
    }

    @Override public synchronized void close() {
        if(stopped && pool.isShutdown())return;
        stopped=true;
        closeQuietly(listener);
        listener=null;
        for(Map.Entry<Socket,LocalSocket> entry:sessions.entrySet()) {
            closeQuietly(entry.getValue());
            closeQuietly(entry.getKey());
        }
        sessions.clear();
        pool.shutdownNow();
    }

    private static void closeQuietly(Closeable stream) {
        if(stream!=null)try{stream.close();}catch(IOException ignored){}
    }
}
