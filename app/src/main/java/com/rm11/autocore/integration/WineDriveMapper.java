package com.rm11.autocore.integration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;

/** Winlator-inspired Wine dosdevices bridge; original implementation, no bundled Winlator code.
 * Maps an accessible real Android filesystem path into Wine without copying the game's files.
 * content:// URIs are intentionally NOT supported: they require a separate SAF bridge.
 */
public final class WineDriveMapper {
    private WineDriveMapper() {}

    public static Path mapExistingGameDirectory(Path winePrefix, Path gameFolder, char letter) throws IOException {
        if (winePrefix == null || gameFolder == null) throw new IOException("Missing directory");
        char drive = Character.toLowerCase(letter);
        if (drive < 'd' || drive > 'y') throw new IOException("Only free letters D: through Y: are permitted");
        Path prefix = winePrefix.toAbsolutePath().normalize();
        Path dosdevices = prefix.resolve("dosdevices");
        if (!Files.isDirectory(prefix, LinkOption.NOFOLLOW_LINKS)
                || !Files.isRegularFile(prefix.resolve(".rm11-prefix-complete"), LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Wine prefix is not committed");
        if (!Files.isDirectory(dosdevices, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(dosdevices))
            throw new IOException("Invalid dosdevices directory");
        Path source = gameFolder.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(source) || !Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)
                || !Files.isReadable(source))
            throw new IOException("Game folder must be a real, readable directory");
        source = source.toRealPath(LinkOption.NOFOLLOW_LINKS);
        if (source.startsWith(prefix)) throw new IOException("Game directory cannot be inside the prefix");
        Path link = dosdevices.resolve(String.valueOf(drive) + ":");
        if (Files.exists(link, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Drive already exists; existing mapping will not be overwritten");
        Files.createSymbolicLink(link, source);
        return link;
    }
}
