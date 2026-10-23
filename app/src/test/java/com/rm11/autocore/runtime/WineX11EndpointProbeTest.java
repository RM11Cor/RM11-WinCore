package com.rm11.autocore.runtime;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineX11EndpointProbeTest {
    private WineX11EndpointProbe.Result runFakeServer(int status, int major) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback)) {
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread thread = new Thread(() -> {
                try (Socket client = server.accept()) {
                    client.setSoTimeout(2000);
                    byte[] setup = new byte[12];
                    new java.io.DataInputStream(client.getInputStream()).readFully(setup);
                    if (setup[0] != 0x6c || setup[2] != 11)
                        throw new IllegalStateException("Not X11 setup 11.0");
                    client.getOutputStream().write(new byte[] {
                        (byte)status, 0, (byte)(major & 255), (byte)(major >>> 8), 0, 0, 0, 0
                    });
                    client.getOutputStream().flush();
                } catch (Throwable error) {
                    failure.set(error);
                }
            }, "rm11-x11-mock");
            thread.start();
            WineX11EndpointProbe.Result result =
                    WineX11EndpointProbe.probe(loopback, server.getLocalPort(), 2000);
            thread.join(2500);
            assertFalse("Mock X11 server must stop", thread.isAlive());
            if (failure.get() != null)
                throw new AssertionError("Mock X11 server failed", failure.get());
            return result;
        }
    }

    @Test public void recognizesX11ProtocolAcceptanceNotOnlyTcpPort() throws Exception {
        WineX11EndpointProbe.Result success = runFakeServer(1, 11);
        assertTrue(success.accepted);
        assertEquals("X11_SETUP_ACCEPTED", success.status);
        assertTrue(success.report().contains("Windows window visible: NOT_VERIFIED"));
    }

    @Test public void rejectsX11AuthFailureOrRequired() throws Exception {
        assertFalse(runFakeServer(0, 11).accepted);
        assertEquals("X11_SETUP_REQUIRES_AUTHENTICATION", runFakeServer(2, 11).status);
    }

    @Test public void differentiatesTcpConnectFromX11ReplyTimeout() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback)) {
            Thread client = new Thread(() -> {
                try (Socket socket = server.accept()) {
                    byte[] setup = new byte[12];
                    new java.io.DataInputStream(socket.getInputStream()).readFully(setup);
                    Thread.sleep(450);
                    // Deliberately remain silent: TCP succeeds, X11 setup does not.
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, "rm11-x11-silent-mock");
            client.start();
            WineX11EndpointProbe.Result got =
                    WineX11EndpointProbe.probe(loopback, server.getLocalPort(), 1000, 130);
            client.join(1500);
            assertFalse("Mock must finish", client.isAlive());
            assertTrue(got.tcpConnected);
            assertFalse(got.accepted);
            assertEquals("X11_TCP_CONNECTED_NO_SETUP_REPLY_TIMEOUT", got.status);
            assertEquals("X11_REPLY_WAIT", got.stage);
            assertTrue(got.report().contains("TCP connection: ESTABLISHED"));
        }
    }

    @Test public void rejectsInvalidOrNonLoopbackTargets() throws Exception {
        assertEquals("BLOCKED_NON_LOOPBACK_OR_INVALID_ARGUMENT",
                WineX11EndpointProbe.probe(InetAddress.getByName("192.0.2.2"), 6000, 200).status);
        assertFalse(runFakeServer(1, 10).accepted);
    }
}
