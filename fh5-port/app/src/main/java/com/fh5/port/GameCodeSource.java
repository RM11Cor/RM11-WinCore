package com.fh5.port;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

/**
 * One read-only facade for two independently-selected sources:
 * original ZIP64 member or directly extracted ForzaHorizon5.exe.
 * All PE mapping and section permissions are checked by GameExeHeaderProbe.
 * Never owns the channel; caller closes its Android SAF descriptor.
 */
public final class GameCodeSource {
    private final SeekableByteChannel channel;
    private final boolean directExe;

    public GameCodeSource(SeekableByteChannel channel, boolean directExe) {
        if(channel==null)throw new IllegalArgumentException("null channel");
        this.channel=channel;
        this.directExe=directExe;
    }
    public boolean isDirectExe() {return directExe;}
    public String kind() {return directExe?"EXTRACTED_PE64_DIRECT":"ZIP64_ARCHIVED_EXE";}
    public GameExeHeaderProbe.Result inspectHeader() throws IOException {
        return directExe?GameExeHeaderProbe.inspectDirectHeader(channel):
            GameExeHeaderProbe.inspect(channel);
    }
    public GameExeHeaderProbe.EntryResult inspectEntry() throws IOException {
        return directExe?GameExeHeaderProbe.inspectDirectEntry(channel):
            GameExeHeaderProbe.inspectEntry(channel);
    }
    public GameExeHeaderProbe.EntryResult inspectAtRva(long rva,int sampleBytes)
            throws IOException {
        return directExe?GameExeHeaderProbe.inspectDirectAtRva(channel,rva,sampleBytes):
            GameExeHeaderProbe.inspectAtRva(channel,rva,sampleBytes);
    }
}
