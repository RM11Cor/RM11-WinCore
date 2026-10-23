package com.rm11.autocore.runtime;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Bounded, opt-in X11 wire handshake with a loopback-only display server.
 *
 * This does not implement an X server or prove Wine has drawn a visible window.
 * XServer XSDL can listen on TCP port 6000 for display :0 when the user starts it.
 * No network host besides 127.0.0.1 is allowed and no authentication bypass occurs.
 */
public final class WineX11EndpointProbe {
    public static final String DISPLAY = "127.0.0.1:0";
    public static final int PORT = 6000;
    private static final int TIMEOUT_MS = 1200;

    private WineX11EndpointProbe() {}

    public static final class Result {
        public final boolean accepted;
        public final String status;
        private Result(boolean accepted, String status) {
            this.accepted = accepted;
            this.status = status;
        }
        public String report() {
            return "RM11_X11_LOOPBACK_WIRE_PROBE_V276\n"
                    + "Display: " + DISPLAY + "\n"
                    + "X11 wire setup: " + status + "\n"
                    + "Wire handshake accepted: " + (accepted ? "YES" : "NO") + "\n"
                    + "Wine winex11 driver initialized: NOT_VERIFIED\n"
                    + "Android-native embedded X server: NOT_IMPLEMENTED\n"
                    + "Windows window visible: NOT_VERIFIED\n";
        }
    }

    public static Result probeLoopbackDisplay0() {
        try {
            return probe(InetAddress.getByName("127.0.0.1"), PORT, TIMEOUT_MS);
        } catch (IOException e) {
            return new Result(false, "LOOPBACK_ADDRESS_UNAVAILABLE");
        }
    }

    /** Package-private to unit test a minimal X11 setup server without Android. */
    static Result probe(InetAddress host, int port, int timeoutMs) {
        if (host == null || !host.isLoopbackAddress() || port < 1 || port > 65535
                || timeoutMs < 100 || timeoutMs > 5000)
            return new Result(false, "BLOCKED_NON_LOOPBACK_OR_INVALID_ARGUMENT");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            // X11 connection setup request, little-endian, protocol 11.0,
            // empty auth name/data. Auth-reject and auth-required remain errors.
            byte[] request = new byte[] {
                    0x6c, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            OutputStream out = socket.getOutputStream();
            out.write(request);
            out.flush();
            byte[] reply = new byte[8];
            new DataInputStream(socket.getInputStream()).readFully(reply);
            int status = reply[0] & 0xff;
            int major = (reply[2] & 0xff) | ((reply[3] & 0xff) << 8);
            if (status == 1 && major == 11)
                return new Result(true, "X11_SETUP_ACCEPTED");
            if (status == 0)
                return new Result(false, "X11_SETUP_REJECTED_OR_AUTH_FAILED");
            if (status == 2)
                return new Result(false, "X11_SETUP_REQUIRES_AUTHENTICATION");
            return new Result(false, "UNEXPECTED_X11_SETUP_REPLY");
        } catch (IOException e) {
            return new Result(false, "X11_CONNECTION_FAILED_" + e.getClass().getSimpleName());
        }
    }
}
