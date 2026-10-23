package com.rm11.autocore.runtime;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.OutputStream;

/**
 * Separate TCP connection, X11 request and reply diagnostics for an opt-in
 * display :0 on THIS Android device only. This never starts an X server or
 * claims Wine/Android window visibility or Vulkan support.
 */
public final class WineX11EndpointProbe {
    public static final String DISPLAY = "127.0.0.1:0";
    public static final int PORT = 6000;
    public static final int EMBEDDED_PORT = 6002;
    public static final String EMBEDDED_DISPLAY = "127.0.0.1:2";
    private static final int CONNECT_TIMEOUT_MS = 4000;
    private static final int REPLY_TIMEOUT_MS = 5000;

    private WineX11EndpointProbe() {}

    public static final class Result {
        public final boolean accepted;
        public final boolean tcpConnected;
        public final String status;
        public final String stage;
        public final long tcpConnectMs;
        public final long totalMs;

        private Result(boolean accepted, boolean tcpConnected, String status,
                       String stage, long tcpConnectMs, long totalMs) {
            this.accepted = accepted;
            this.tcpConnected = tcpConnected;
            this.status = status;
            this.stage = stage;
            this.tcpConnectMs = tcpConnectMs;
            this.totalMs = totalMs;
        }
        public String report() { return reportForDisplay(DISPLAY); }
        public String reportForDisplay(String display) {
            return "RM11_X11_STAGE_DIAGNOSTICS_V277\n"
                    + "Display: " + display + "\n"
                    + "TCP connection: " + (tcpConnected ? "ESTABLISHED" : "NOT_ESTABLISHED") + "\n"
                    + "Last completed protocol stage: " + stage + "\n"
                    + "TCP connect time ms: " + (tcpConnected ? Long.toString(tcpConnectMs) : "N/A") + "\n"
                    + "Total probe time ms: " + totalMs + "\n"
                    + "X11 wire setup: " + status + "\n"
                    + "Wire handshake accepted: " + (accepted ? "YES" : "NO") + "\n"
                    + "Wine winex11 driver initialized: NOT_VERIFIED\n"
                    + "Android-native embedded X server: NOT_IMPLEMENTED\n"
                    + "Windows window visible: NOT_VERIFIED\n";
        }
    }

    public static Result probeLoopbackDisplay0() {
        try {
            return probe(InetAddress.getByName("127.0.0.1"), PORT,
                    CONNECT_TIMEOUT_MS, REPLY_TIMEOUT_MS);
        } catch (IOException e) {
            return new Result(false, false, "LOOPBACK_ADDRESS_UNAVAILABLE",
                    "BEFORE_CONNECT", 0, 0);
        }
    }

    /**
     * The opt-in embedded Android X11 View owns this port; it is not XSDL.
     * Report a successful wire handshake only, not a rendered Windows image.
     */
    public static Result probeEmbeddedDisplay2() {
        try {
            return probe(InetAddress.getByName("127.0.0.1"), EMBEDDED_PORT,
                    CONNECT_TIMEOUT_MS, REPLY_TIMEOUT_MS);
        } catch (IOException e) {
            return new Result(false, false, "LOOPBACK_ADDRESS_UNAVAILABLE",
                    "BEFORE_CONNECT", 0, 0);
        }
    }

    /** Old test hook remains intact; timeouts can be tested independently. */
    static Result probe(InetAddress host, int port, int timeoutMs) {
        return probe(host, port, timeoutMs, timeoutMs);
    }

    /** Package-private so tests can simulate each X11 stage without Android. */
    static Result probe(InetAddress host, int port, int connectTimeoutMs, int replyTimeoutMs) {
        long start = System.nanoTime();
        if (host == null || !host.isLoopbackAddress() || port < 1 || port > 65535
                || connectTimeoutMs < 100 || connectTimeoutMs > 6000
                || replyTimeoutMs < 100 || replyTimeoutMs > 6000)
            return result(false, false, "BLOCKED_NON_LOOPBACK_OR_INVALID_ARGUMENT",
                    "BEFORE_CONNECT", 0, start);
        try (Socket socket = new Socket()) {
            try {
                socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            } catch (SocketTimeoutException e) {
                return result(false, false, "X11_TCP_CONNECT_TIMEOUT",
                        "TCP_CONNECT", 0, start);
            } catch (IOException e) {
                return result(false, false, "X11_TCP_CONNECT_FAILED_" + e.getClass().getSimpleName(),
                        "TCP_CONNECT", 0, start);
            }
            long tcpMs = (System.nanoTime() - start) / 1000000L;
            socket.setSoTimeout(replyTimeoutMs);
            // X11 setup: little-endian, version 11.0, no credentials sent.
            // A server requiring authentication must explicitly reject/ask.
            byte[] setup = new byte[] {
                    0x6c, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            try {
                OutputStream output = socket.getOutputStream();
                output.write(setup);
                output.flush();
            } catch (IOException e) {
                return result(false, true, "X11_TCP_CONNECTED_SETUP_WRITE_FAILED_"
                        + e.getClass().getSimpleName(), "X11_REQUEST", tcpMs, start);
            }
            byte[] reply = new byte[8];
            try {
                new DataInputStream(socket.getInputStream()).readFully(reply);
            } catch (SocketTimeoutException e) {
                return result(false, true, "X11_TCP_CONNECTED_NO_SETUP_REPLY_TIMEOUT",
                        "X11_REPLY_WAIT", tcpMs, start);
            } catch (EOFException e) {
                return result(false, true, "X11_TCP_CONNECTED_SETUP_REPLY_TRUNCATED",
                        "X11_REPLY_WAIT", tcpMs, start);
            } catch (IOException e) {
                return result(false, true, "X11_TCP_CONNECTED_SETUP_READ_FAILED_"
                        + e.getClass().getSimpleName(), "X11_REPLY_WAIT", tcpMs, start);
            }
            int status = reply[0] & 0xff;
            int major = (reply[2] & 0xff) | ((reply[3] & 0xff) << 8);
            if (status == 1 && major == 11)
                return result(true, true, "X11_SETUP_ACCEPTED",
                        "X11_PROTOCOL_11_ACCEPTED", tcpMs, start);
            if (status == 0)
                return result(false, true, "X11_SETUP_REJECTED_OR_AUTH_FAILED",
                        "X11_PROTOCOL_REPLY", tcpMs, start);
            if (status == 2)
                return result(false, true, "X11_SETUP_REQUIRES_AUTHENTICATION",
                        "X11_PROTOCOL_REPLY", tcpMs, start);
            return result(false, true, "X11_UNEXPECTED_SETUP_REPLY",
                    "X11_PROTOCOL_REPLY", tcpMs, start);
        } catch (IOException e) {
            return result(false, false, "X11_SOCKET_SETUP_FAILED_" + e.getClass().getSimpleName(),
                    "BEFORE_CONNECT", 0, start);
        }
    }

    private static Result result(boolean accepted, boolean connected, String status,
                                 String stage, long tcpMs, long start) {
        return new Result(accepted, connected, status, stage, tcpMs,
                Math.max(0L, (System.nanoTime() - start) / 1000000L));
    }
}
