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
            s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(),
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
