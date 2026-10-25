package com.rm11.autocore.runtime;

import android.graphics.Bitmap;
import android.os.Handler;
import android.view.PixelCopy;
import android.view.SurfaceView;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashSet;
import java.util.Set;

/**
 * Read-only proof of where X11 rendering stops. An accepted DISPLAY socket
 * does not prove there are mapped windows or any pixels on Android's Surface.
 * No screenshots, window titles, or user files are saved; only counts.
 */
public final class NativeDesktopVisualEvidence {
    private static final int MAX_X11_REPLY = 1024 * 1024;
    private NativeDesktopVisualEvidence() {}

    private static int u16(byte[] b, int p) {
        return (b[p] & 255) | ((b[p + 1] & 255) << 8);
    }
    private static long u32(byte[] b, int p) {
        return (b[p] & 255L) | ((b[p + 1] & 255L) << 8)
                | ((b[p + 2] & 255L) << 16) | ((b[p + 3] & 255L) << 24);
    }
    private static void put32(byte[] b, int p, long v) {
        for (int i = 0; i < 4; ++i) b[p + i] = (byte) (v >>> (8 * i));
    }
    private static byte[] xReply(DataInputStream input) throws IOException {
        byte[] head = new byte[32];
        input.readFully(head);
        if ((head[0] & 255) != 1) {
            throw new IOException("X11_CORE_REPLY_TYPE_" + (head[0] & 255));
        }
        long extra = u32(head, 4) * 4L;
        if (extra < 0 || extra > MAX_X11_REPLY)
            throw new IOException("X11_REPLY_TOO_LARGE");
        byte[] all = new byte[32 + (int) extra];
        System.arraycopy(head, 0, all, 0, 32);
        input.readFully(all, 32, (int) extra);
        return all;
    }
    private static byte[] request(OutputStream out, DataInputStream in,
                                  int opcode, long resource) throws IOException {
        byte[] b = new byte[8];
        b[0] = (byte) opcode;
        b[2] = 2; // X11 request is 2 four-byte words.
        put32(b, 4, resource);
        out.write(b);
        out.flush();
        return xReply(in);
    }

    /** Query the root's direct children and each child's map state. */
    public static String auditX11() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),
                    NativeX11TcpBridge.TCP_PORT), 2000);
            s.setSoTimeout(1900);
            DataInputStream in = new DataInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();
            out.write(new byte[]{'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            out.flush();
            byte[] setup = new byte[8];
            in.readFully(setup);
            if ((setup[0] & 255) != 1)
                return "RM11_V410_X11_SETUP_REJECTED=" + (setup[0] & 255);
            long extra = u16(setup, 6) * 4L;
            if (extra < 40 || extra > MAX_X11_REPLY)
                throw new IOException("X11_SETUP_INVALID_LENGTH");
            byte[] cfg = new byte[(int) extra];
            in.readFully(cfg);
            int screens = cfg[20] & 255;
            int formats = cfg[21] & 255;
            int vendor = u16(cfg, 16);
            long screenOffset = 32L + ((vendor + 3L) & ~3L) + formats * 8L;
            if (screens < 1 || screenOffset + 40 > cfg.length)
                throw new IOException("X11_NO_ROOT_SCREEN");
            long root = u32(cfg, (int) screenOffset);
            int screenW = u16(cfg, (int) screenOffset + 20);
            int screenH = u16(cfg, (int) screenOffset + 22);
            byte[] children = request(out, in, 15, root); // QueryTree
            int count = u16(children, 16);
            if (32L + count * 4L > children.length)
                throw new IOException("X11_QUERY_TREE_TRUNCATED");
            int viewable = 0, unmapped = 0, unviewable = 0, errors = 0;
            int checked = Math.min(count, 96);
            for (int i = 0; i < checked; ++i) {
                long id = u32(children, 32 + i * 4);
                try {
                    byte[] attr = request(out, in, 3, id); // GetWindowAttributes
                    switch (attr[26] & 255) { // map_state
                        case 2: viewable++; break;
                        case 1: unviewable++; break;
                        default: unmapped++; break;
                    }
                } catch (IOException failure) {
                    errors++;
                    // Do not continue on a protocol error; its reply may
                    // desynchronize subsequent sequence numbers.
                    break;
                }
            }
            return "RM11_V410_X11_ROOT_WINDOW_QUERY_OK\n"
                    + "x11_root_pixels=" + screenW + "x" + screenH + "\n"
                    + "x11_root_children=" + count + "\n"
                    + "x11_children_examined=" + checked + "\n"
                    + "x11_children_viewable=" + viewable + "\n"
                    + "x11_children_unviewable=" + unviewable + "\n"
                    + "x11_children_unmapped=" + unmapped + "\n"
                    + "x11_attribute_errors=" + errors + "\n"
                    + "x11_children_capped=" + (count > 96) + "\n";
        } catch (Exception e) {
            return "RM11_V410_X11_WINDOW_QUERY_FAILED="
                    + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    /**
     * ICCCM WM_CLASS (predefined X11 atom 67) identifies the Winefile client,
     * not the constantly changing window title. No title or path is logged.
     * Query properties read-only; cap replies and reject non-string formats.
     */
    private static boolean isWinefileX11Window(OutputStream out, DataInputStream in,
                                                long window) throws IOException {
        byte[] getProperty=new byte[24];
        getProperty[0]=20;              // X11 GetProperty
        getProperty[2]=6;               // six 4-byte words
        put32(getProperty,4,window);
        put32(getProperty,8,67);        // XA_WM_CLASS
        put32(getProperty,12,31);       // XA_STRING
        put32(getProperty,20,32);       // read at most 128 bytes
        out.write(getProperty);
        out.flush();
        byte[] reply=xReply(in);
        int format=reply[1]&255;
        int count=(int)u32(reply,16);
        if(format!=8 || u32(reply,8)!=31 || count<1 || count>128
                || 32+count>reply.length)return false;
        String cls=new String(reply,32,count,java.nio.charset.StandardCharsets.ISO_8859_1)
                .toLowerCase(java.util.Locale.ROOT);
        return cls.contains("winefile");
    }

    /**
     * Native-X11 geometry repair for Winefile's real TOP-LEVEL window.
     * Device diagnosis v4.0.17 shows X11 root and Android Surface both
     * 2688x1216, but the only mapped Winefile top-level covers roughly
     * 75% of the viewport. Scaling the X11 root does not fix a WM frame
     * that itself remains 75%. X11 ConfigureWindow changes that frame.
     *
     * Safety rules:
     * - Touch only ONE mapped direct child of the actual X11 root
     * - Never touch another application's windows when several are mapped
     * - Never adjust root, unmapped children, or nested Win32 MDI windows
     * - Measure before/after with GetGeometry; do not claim success blindly
     * - Do not read window titles, clipboard, file paths, or user data
     */
    public static String fitSingleVisibleTopLevelWindow() {
        try (Socket sock=new Socket()) {
            sock.connect(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"),NativeX11TcpBridge.TCP_PORT),2200);
            sock.setSoTimeout(2400);
            DataInputStream in=new DataInputStream(sock.getInputStream());
            OutputStream out=sock.getOutputStream();
            out.write(new byte[]{'l',0,11,0,0,0,0,0,0,0,0,0});
            out.flush();
            byte[] pre=new byte[8];
            in.readFully(pre);
            if((pre[0]&255)!=1)return "RM11_V418_X11_SETUP_REFUSED";
            int extra=u16(pre,6)*4;
            if(extra<40||extra>MAX_X11_REPLY)
                return "RM11_V418_X11_SETUP_TOO_LARGE";
            byte[] config=new byte[extra];
            in.readFully(config);
            int screens=config[20]&255,formats=config[21]&255,vendor=u16(config,16);
            long off=32L+((vendor+3L)&~3L)+formats*8L;
            if(screens==0||off+40>config.length)
                return "RM11_V418_NO_ROOT_INFO";
            long root=u32(config,(int)off);
            int rootW=u16(config,(int)off+20),rootH=u16(config,(int)off+22);
            if(rootW<640||rootH<320||rootW>8192||rootH>8192)
                return "RM11_V418_ROOT_SIZE_INVALID";
            byte[] tree=request(out,in,15,root);
            int count=u16(tree,16);
            if(count<1||count>96||32L+count*4L>tree.length)
                return "RM11_V418_ROOT_CHILDREN_UNEXPECTED_"+count;
            int mapped=0, winefileClassMatches=0;
            long onlyMapped=0, verifiedWinefile=0;
            for(int i=0;i<count;i++) {
                long window=u32(tree,32+i*4);
                byte[] attrs=request(out,in,3,window);
                if((attrs[26]&255)!=2)continue;
                mapped++;
                onlyMapped=window;
                // v423: do not let transient X11 tool windows block fullscreen.
                // When multiple windows are mapped, use the stable WM_CLASS
                // of Winefile instead of selecting the first or largest.
                if(isWinefileX11Window(out,in,window)) {
                    winefileClassMatches++;
                    verifiedWinefile=window;
                }
            }
            final long target;
            if(winefileClassMatches==1) {
                target=verifiedWinefile;
            }else if(mapped==1 && winefileClassMatches==0) {
                // v421 backward-compatible, guarded by geometry below. Never
                // use this fallback if any competing top-level is mapped.
                target=onlyMapped;
            }else {
                return "RM11_V423_X11_NO_UNAMBIGUOUS_WINEFILE"
                        +"\\nviewable_root_windows="+mapped
                        +"\\nwinefile_class_matches="+winefileClassMatches;
            }
            byte[] before=request(out,in,14,target); // X11 GetGeometry
            int x=(short)u16(before,12),y=(short)u16(before,14);
            int ww=u16(before,16),hh=u16(before,18);
            String old=ww+"x"+hh+"@"+x+","+y;
            if(ww>=rootW-24&&hh>=rootH-24&&x<=8&&y<=8)
                return "RM11_V418_MAIN_FRAME_ALREADY_FILLS_SCREEN="+old
                        +" root="+rootW+"x"+rootH;
            // Restrict to a plausible Winefile desktop frame. Do not
            // enlarge a small dialog or small unrelated mapped application.
            if(ww<rootW/3||hh<rootH/3||ww>rootW||hh>rootH)
                return "RM11_V418_FRAME_OUTSIDE_SAFE_RANGE="+old
                        +" root="+rootW+"x"+rootH;
            // X11 ConfigureWindow opcode 12; value-mask x|y|width|height.
            // Request length: (12+16)/4 = 7 4-byte units.
            byte[] move=new byte[28];
            move[0]=12;move[2]=7;put32(move,4,target);
            move[8]=15;
            put32(move,12,0);put32(move,16,0);
            put32(move,20,rootW);put32(move,24,rootH);
            out.write(move);out.flush();
            byte[] after=request(out,in,14,target);
            int finalX=(short)u16(after,12),finalY=(short)u16(after,14);
            int finalW=u16(after,16),finalH=u16(after,18);
            String now=finalW+"x"+finalH+"@"+finalX+","+finalY;
            boolean fitted=finalW>=rootW-24&&finalH>=rootH-24;
            return "RM11_V418_X11_MAIN_FRAME_"
                    +(fitted?"RESIZED_VERIFIED":"RESIZE_NOT_CONFIRMED")
                    +"\nbefore="+old+"\nafter="+now
                    +"\nroot="+rootW+"x"+rootH+"\nvisible_root_children="+mapped;
        }catch(Exception error) {
            return "RM11_V418_X11_WINDOW_RESIZE_FAILED="
                    +error.getClass().getSimpleName();
        }
    }

    /**
     * Strict visual readiness for RM11 v4.0.20. A totally white unpopulated
     * framebuffer, Wine blue background, or split black/white display MUST
     * NOT end the intro animation. PixelCopy sees the native X11 Surface,
     * not the Android curtain. No screenshots or user file data are stored.
     */
    public static void auditWinefileReady(SurfaceView source,Handler main,
                                           java.util.function.Consumer<String> done) {
        if(source==null || source.getWidth()<640 || source.getHeight()<320
                || !source.getHolder().getSurface().isValid()) {
            done.accept("RM11_V420_GUI_READY=false\nreason=NO_LANDSCAPE_SURFACE");
            return;
        }
        final Bitmap sample=Bitmap.createBitmap(192,108,Bitmap.Config.ARGB_8888);
        try {
            PixelCopy.request(source,sample,result->{
                try {
                    if(result!=PixelCopy.SUCCESS) {
                        done.accept("RM11_V420_GUI_READY=false\npixelcopy="+result);
                        return;
                    }
                    int white=0,blue=0,ink=0,colors=0;
                    java.util.Set<Integer> unique=new java.util.HashSet<>();
                    for(int y=0;y<108;y++)for(int x=0;x<192;x++){
                        int p=sample.getPixel(x,y);
                        int r=(p>>>16)&255,g=(p>>>8)&255,b=p&255;
                        int low=Math.min(r,Math.min(g,b));
                        int high=Math.max(r,Math.max(g,b));
                        if(low>221 && high-low<35)white++;
                        if(b>r+38 && b>g+13 && b>115)blue++;
                        if(y>1 && y<24 && x<120 && high<175)ink++;
                        if(high-low>35)colors++;
                        if(unique.size()<96)unique.add(((r>>4)<<8)|((g>>4)<<4)|(b>>4));
                    }
                    // White full viewport plus actual blue selected drive
                    // and black upper labels. The older near-black test
                    // incorrectly released on incomplete solid-white frames.
                    boolean ready=white>=15800 && blue>=6 &&
                            ink>=8 && unique.size()>=18;
                    done.accept("RM11_V420_GUI_READY="+ready
                            +"\nwhite_pixels="+white
                            +"\nblue_selection_pixels="+blue
                            +"\nupper_toolbar_ink="+ink
                            +"\ncolor_variations="+colors
                            +"\nunique_16color_buckets="+unique.size()
                            +"\nsurface_pixels="+source.getWidth()+"x"+source.getHeight());
                }finally { sample.recycle(); }
            },main);
        }catch(RuntimeException ex){
            sample.recycle();
            done.accept("RM11_V420_GUI_READY=false\nreason="+ex.getClass().getSimpleName());
        }
    }

    /**
     * PixelCopy reads the actual SurfaceView composited pixel source. A black
     * Surface is evidence only; it does not identify whether the cause is Wine,
     * X.Org geometry, or the EGL renderer.
     */
    public static void auditSurface(SurfaceView source, Handler main,
                                    java.util.function.Consumer<String> done) {
        if (source == null || source.getWidth() < 1 || source.getHeight() < 1
                || !source.getHolder().getSurface().isValid()) {
            done.accept("RM11_V410_ANDROID_SURFACE_NOT_READY");
            return;
        }
        final int w = source.getWidth(), h = source.getHeight();
        final Bitmap pixels = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888);
        try {
            PixelCopy.request(source, pixels, result -> {
                try {
                    if (result != PixelCopy.SUCCESS) {
                        done.accept("RM11_V410_PIXELCOPY_RESULT=" + result);
                        return;
                    }
                    int black = 0, opaque = 0, varied = 0;
                    Set<Integer> unique = new HashSet<>();
                    for (int y = 0; y < 64; y++) for (int x = 0; x < 64; x++) {
                        int argb = pixels.getPixel(x, y);
                        int r = (argb >>> 16) & 255;
                        int g = (argb >>> 8) & 255;
                        int b = argb & 255;
                        if (((argb >>> 24) & 255) >= 250) opaque++;
                        if (r < 16 && g < 16 && b < 16) black++;
                        if (Math.max(r, Math.max(g, b)) - Math.min(r, Math.min(g, b)) > 12)
                            varied++;
                        if (unique.size() < 512) unique.add(argb & 0xffffff);
                    }
                    done.accept("RM11_V410_ANDROID_SURFACE_PIXELCOPY_OK\n"
                            + "android_surface_pixels=" + w + "x" + h + "\n"
                            + "sample_pixels=4096\n"
                            + "near_black_pixels=" + black + "\n"
                            + "opaque_pixels=" + opaque + "\n"
                            + "chroma_varied_pixels=" + varied + "\n"
                            + "unique_rgb_colors_capped512=" + unique.size() + "\n"
                            + "visual_text_recognition=NOT_PERFORMED\n");
                } finally {
                    pixels.recycle();
                }
            }, main);
        } catch (RuntimeException e) {
            pixels.recycle();
            done.accept("RM11_V410_PIXELCOPY_EXCEPTION=" + e.getClass().getSimpleName());
        }
    }
}
