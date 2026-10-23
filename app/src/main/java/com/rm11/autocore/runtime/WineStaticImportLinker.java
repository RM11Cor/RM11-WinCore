package com.rm11.autocore.runtime;

import com.rm11.autocore.PeImportReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;

/**
 * Bounded transitive PE import resolution for the explicitly chosen EXE pilot.
 *
 * Reads ONLY the selected app-private PE and PE builtins shipped with RM11's
 * pinned Wine aarch64-windows runtime. Creates only non-overwriting System32
 * symlinks pointing back inside the app-private Wine bundle, no downloaded
 * DLLs or executable copies. It is not Wine's full loader, graphics support,
 * a license bypass, or generic game compatibility.
 */
public final class WineStaticImportLinker {
    private static final int MAX_DLLS = 96;
    private static final int MAX_EDGES = 384;
    private static final int MAX_REPORTED = 30;
    private WineStaticImportLinker() {}

    public static String prepare(RuntimeLayout p, Path selectedExe) {
        StringBuilder out = new StringBuilder("RM11_TRANSITIVE_WINE_PE_IMPORTS_V274\n");
        try {
            ExternalExePilotPolicy.validate(p, selectedExe);
            Path trusted = p.appFiles.toRealPath();
            Path prefix = p.winePrefix.toRealPath();
            Path root = p.wineDllRoot.resolve("aarch64-windows");
            Path imageRoot = root.toRealPath();
            Path system32 = p.winePrefix.resolve("drive_c/windows/system32");
            if (!prefix.startsWith(trusted) || !imageRoot.startsWith(trusted)
                    || !Files.isDirectory(system32, LinkOption.NOFOLLOW_LINKS)
                    || !system32.toRealPath().startsWith(prefix)
                    || !Files.isRegularFile(p.winePrefixMarker(), LinkOption.NOFOLLOW_LINKS))
                return out.append("result=BLOCKED_UNTRUSTED_APP_PRIVATE_ROOT\n").toString();

            ArrayDeque<String> queue = new ArrayDeque<>();
            try (FileChannel ch = FileChannel.open(selectedExe, StandardOpenOption.READ)) {
                PeImportReader.Info imports = PeImportReader.read(ch);
                if (!"x86-64".equals(imports.architecture))
                    return out.append("result=BLOCKED_WRONG_GUEST_ARCH\n").toString();
                queue.addAll(imports.importedDlls);
                out.append("directImports=").append(imports.importedDlls.size()).append('\n');
            }
            Set<String> seen = new HashSet<>();
            int linked=0, existing=0, skipped=0, missing=0, scanned=0, edges=0, reported=0;
            boolean cap=false;
            while (!queue.isEmpty()) {
                if (seen.size() >= MAX_DLLS || edges >= MAX_EDGES) {
                    cap = true;
                    break;
                }
                String dll = queue.removeFirst();
                if (!dll.matches("[a-z0-9_.+-]{3,128}\\.dll")) {
                    skipped++;
                    continue;
                }
                if (!seen.add(dll)) continue;
                Path file = root.resolve(dll);
                if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                    missing++;
                    if(reported++<MAX_REPORTED) out.append("NOT_BUNDLED ").append(dll).append('\n');
                    continue;
                }
                Path resolved=file.toRealPath();
                if (!resolved.startsWith(imageRoot) || !Files.isRegularFile(resolved)
                        || Files.size(resolved)<4096) {
                    skipped++;
                    if(reported++<MAX_REPORTED) out.append("REJECTED_SOURCE ").append(dll).append('\n');
                    continue;
                }
                try (InputStream in=Files.newInputStream(resolved)) {
                    if(in.read()!='M' || in.read()!='Z') {
                        skipped++;
                        if(reported++<MAX_REPORTED) out.append("NOT_PE ").append(dll).append('\n');
                        continue;
                    }
                }
                Path alias=system32.resolve(dll);
                if(Files.exists(alias, LinkOption.NOFOLLOW_LINKS)) {
                    if(!Files.isSymbolicLink(alias)) {
                        skipped++;
                        if(reported++<MAX_REPORTED) out.append("EXISTING_FILE_PRESERVED ").append(dll).append('\n');
                        continue;
                    }
                    try {
                        if(!alias.toRealPath().equals(resolved)) {
                            skipped++;
                            if(reported++<MAX_REPORTED) out.append("EXISTING_SYMLINK_PRESERVED ").append(dll).append('\n');
                            continue;
                        }
                    } catch (IOException e) {
                        skipped++;
                        if(reported++<MAX_REPORTED) out.append("BROKEN_SYMLINK_PRESERVED ").append(dll).append('\n');
                        continue;
                    }
                    existing++;
                } else {
                    Files.createSymbolicLink(alias, resolved);
                    if (!Files.isRegularFile(alias)) {
                        skipped++;
                        if(reported++<MAX_REPORTED) out.append("UNREADABLE_ALIAS ").append(dll).append('\n');
                        continue;
                    }
                    linked++;
                    if(reported++<MAX_REPORTED) out.append("LINKED ").append(dll).append('\n');
                }
                // Traverse only Wine-shipped ARM64 PE builtins. The user-selected
                // guest PE may be x64; its runtime builtins must be AArch64 PE.
                try (FileChannel in = FileChannel.open(file, StandardOpenOption.READ)) {
                    PeImportReader.Info imports = PeImportReader.read(in);
                    if(!"ARM64".equals(imports.architecture)) {
                        skipped++;
                        if(reported++<MAX_REPORTED) out.append("WRONG_BUILTIN_ARCH ").append(dll).append('\n');
                        continue;
                    }
                    scanned++;
                    for(String dependency : imports.importedDlls) {
                        if(++edges>MAX_EDGES) {cap=true;break;}
                        if(!seen.contains(dependency)) queue.addLast(dependency);
                    }
                    if(cap)break;
                }
            }
            out.append("linked=").append(linked).append(" existingTrusted=").append(existing)
               .append(" missingBundled=").append(missing).append(" skipped=").append(skipped)
               .append(" scannedArm64Pe=").append(scanned).append(" importEdges=").append(edges)
               .append(" visited=").append(seen.size()).append('\n');
            out.append("result=").append(cap?"BOUNDED_GRAPH_LIMIT_REACHED":"BOUNDED_SCAN_COMPLETED").append('\n');
            out.append("missingBundled may include API-set DLL names resolved by Wine; not proof of load failure\n");
            return out.toString();
        } catch(Exception e) {
            return out.append("result=BLOCKED_OR_ERROR_")
                    .append(e.getClass().getSimpleName()).append('\n').toString();
        }
    }
}
