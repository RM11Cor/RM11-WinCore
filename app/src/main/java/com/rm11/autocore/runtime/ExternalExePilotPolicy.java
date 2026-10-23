package com.rm11.autocore.runtime;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Pilot phase: one explicitly selected small standalone Windows x86-64 EXE.
 * This is a HEADER and app-private path policy, NOT an antivirus scanner.
 * No arbitrary native ELF execution, game-directory access or copied assets.
 */
public final class ExternalExePilotPolicy {
    public static final long MAX_EXE_BYTES = 16L * 1024L * 1024L;

    private ExternalExePilotPolicy() {}

    /** Read the Windows PE32+ subsystem after policy validation.
     * 2=GUI, 3=console. Do not guess from name or extension.
     */
    public static int readPeSubsystem(RuntimeLayout layout, Path selected) throws IOException {
        validate(layout, selected);
        try (RandomAccessFile in = new RandomAccessFile(selected.toFile(), "r")) {
            in.seek(0x3c);
            long peOffset = Integer.toUnsignedLong(Integer.reverseBytes(in.readInt()));
            in.seek(peOffset + 24 + 68);
            return Short.toUnsignedInt(Short.reverseBytes(in.readShort()));
        }
    }

    public static void validate(RuntimeLayout layout, Path selected) throws IOException {
        Path privateRoot = layout.appFiles.toRealPath();
        Path importDir = layout.appFiles.resolve("external-exe-pilot");
        if (!Files.isDirectory(importDir, LinkOption.NOFOLLOW_LINKS) ||
                !importDir.toRealPath().startsWith(privateRoot))
            throw new IOException("Private EXE test directory not available");
        if (selected == null || Files.isSymbolicLink(selected) ||
                !Files.isRegularFile(selected, LinkOption.NOFOLLOW_LINKS) ||
                !selected.toRealPath().getParent().equals(importDir.toRealPath()))
            throw new IOException("EXE must be the selected app-private staged file");
        String name = selected.getFileName().toString();
        if (!name.startsWith("rm11-import-") || !name.endsWith(".exe"))
            throw new IOException("Invalid bounded pilot filename");
        long size = Files.size(selected);
        if (size < 512 || size > MAX_EXE_BYTES)
            throw new IOException("Standalone EXE must be 512 bytes to 16 MiB");
        try (RandomAccessFile in = new RandomAccessFile(selected.toFile(), "r")) {
            if (in.readUnsignedByte()!='M' || in.readUnsignedByte()!='Z')
                throw new IOException("Windows DOS MZ header not found");
            in.seek(0x3c);
            long peOffset = Integer.toUnsignedLong(Integer.reverseBytes(in.readInt()));
            if (peOffset < 0x40 || peOffset > 4096 || peOffset + 26 > size)
                throw new IOException("Invalid PE offset");
            in.seek(peOffset);
            if (in.readUnsignedByte()!='P' || in.readUnsignedByte()!='E' ||
                    in.readUnsignedByte()!=0 || in.readUnsignedByte()!=0)
                throw new IOException("Invalid PE signature");
            int machine = Short.toUnsignedInt(Short.reverseBytes(in.readShort()));
            if (machine != 0x8664)
                throw new IOException("Only x86-64 PE64 EXE is supported in this pilot");
            in.seek(peOffset + 24);
            int optionalMagic = Short.toUnsignedInt(Short.reverseBytes(in.readShort()));
            if (optionalMagic != 0x20b)
                throw new IOException("PE32+ optional header required");
        }
    }
}
