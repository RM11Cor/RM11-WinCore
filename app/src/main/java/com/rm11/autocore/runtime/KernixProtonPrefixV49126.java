package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Separate immutable Proton package template from an app-private writable
 * prefix. Wineboot must NEVER mutate the signed-source template or the legacy
 * Wine prefix. Fail closed on unknown directories and foreign DOS links.
 */
public final class KernixProtonPrefixV49126 {
    private KernixProtonPrefixV49126(){}
    private static final String OWNER=".kernix-p11-owned-prefix-v49126";
    private static final String VALUE="KERNIX_P11_PREFIX_V49126";
    private static final int MAX_ENTRIES=2500;
    private static final long MAX_BYTES=600L*1024*1024;
    public static Path writableRoot(Path appFiles){
        return appFiles.toAbsolutePath().normalize().resolve(
            "imagefs/home/kernix-proton/prefixes/default");
    }
    private static boolean plainFile(Path p)throws IOException{
        return !Files.isSymbolicLink(p)
            &&Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
            &&Files.size(p)>16;
    }
    private static void requireTree(Path root,boolean marker)throws IOException {
        if(Files.isSymbolicLink(root)
            ||!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("P11_PREFIX_TREE_NOT_DIRECTORY");
        for(String file:new String[]{"system.reg","user.reg","userdef.reg"}){
            if(!plainFile(root.resolve(file)))
                throw new IOException("P11_PREFIX_REGISTRY_MISSING:"+file);
        }
        Path device=root.resolve("dosdevices");
        Path c=device.resolve("c:");
        if(Files.isSymbolicLink(device)
            ||!Files.isDirectory(device,LinkOption.NOFOLLOW_LINKS)
            ||!Files.isSymbolicLink(c)
            ||!Path.of("../drive_c").equals(Files.readSymbolicLink(c))
            ||!Files.isDirectory(root.resolve("drive_c/windows/system32"),
                    LinkOption.NOFOLLOW_LINKS))
            throw new IOException("P11_PREFIX_DEVICE_OR_SYSTEM32_UNSAFE");
        // Wineboot may create the standard Z: root mapping inside its
        // PRIVATE writable prefix. Reject inherited Winlator D/E links and
        // all arbitrary Z: destinations. The signed template remains strict.
        for(String letter:new String[]{"d:","e:","z:"}){
            Path link=device.resolve(letter);
            if(Files.exists(link,LinkOption.NOFOLLOW_LINKS)){
                boolean ownWinebootZ=marker&&"z:".equals(letter)
                    &&Files.isSymbolicLink(link)
                    &&Path.of("/").equals(Files.readSymbolicLink(link));
                if(!ownWinebootZ)
                    throw new IOException("P11_FOREIGN_DOS_LINK_PRESENT:"+letter);
            }
        }
        if(marker){
            Path owner=root.resolve(OWNER);
            if(!plainFile(owner)
                ||!VALUE.equals(new String(Files.readAllBytes(owner),
                   StandardCharsets.US_ASCII).trim()))
                throw new IOException("P11_WRITABLE_PREFIX_OWNER_MISMATCH");
        }
    }
    public static boolean ready(Path appFiles){
        try{
            requireTree(writableRoot(appFiles),true);
            return true;
        }catch(Exception ignored){return false;}
    }
    public static void requireWritable(Path wineRoot,Path prefix)
            throws IOException{
        // WineRoot is the exact engine slot under imagefs/opt.
        Path appFiles=wineRoot.getParent().getParent().getParent();
        Path expected= writableRoot(appFiles);
        if(!expected.equals(prefix.toAbsolutePath().normalize())
            ||Files.isSymbolicLink(prefix))
            throw new IOException("P11_WINEBOOT_TEMPLATE_OR_OTHER_PREFIX_FORBIDDEN");
        requireTree(prefix,true);
    }
    private static void deleteOnlyOwnedStage(Path stage)throws IOException {
        Path owner=stage.resolve(OWNER);
        if(Files.isSymbolicLink(stage)
            ||!Files.isDirectory(stage,LinkOption.NOFOLLOW_LINKS)
            ||!plainFile(owner)
            ||!VALUE.equals(new String(Files.readAllBytes(owner),
                StandardCharsets.US_ASCII).trim()))
            throw new IOException("P11_UNKNOWN_INTERRUPTED_STAGE");
        Files.walkFileTree(stage,new SimpleFileVisitor<Path>(){
            @Override public FileVisitResult visitFile(Path file,
                    BasicFileAttributes attrs)throws IOException{
                if(!file.normalize().startsWith(stage))throw new IOException("P11_STAGE_ESCAPE");
                if(Files.isSymbolicLink(file)
                    &&(!file.equals(stage.resolve("dosdevices/c:"))
                       ||!Path.of("../drive_c").equals(Files.readSymbolicLink(file))))
                    throw new IOException("P11_UNEXPECTED_STAGE_LINK");
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(
                    Path dir,IOException err)throws IOException{
                if(err!=null)throw err;
                if(!dir.normalize().startsWith(stage))throw new IOException("P11_STAGE_ESCAPE");
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
    /** Copy-once without touching any user prefix or game data. */
    public static synchronized Path prepareDefault(Path appFiles)throws IOException{
        if(appFiles==null)throw new IOException("P11_NO_APP_FILES");
        Path root=appFiles.toAbsolutePath().normalize();
        Path template=KernixProtonFexInstallerV49121.slotRoot(root).resolve("prefix");
        requireTree(template,false);
        Path target=writableRoot(root);
        if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)){
            requireTree(target,true);
            return target; // NEVER overwrite a possibly modified prefix.
        }
        Path parent=target.getParent();
        if(Files.isSymbolicLink(parent))throw new IOException("P11_PREFIX_PARENT_SYMLINK");
        Files.createDirectories(parent);
        Path stage=parent.resolve(".default.installing");
        if(Files.exists(stage,LinkOption.NOFOLLOW_LINKS))
            deleteOnlyOwnedStage(stage);
        Files.createDirectory(stage);
        Files.write(stage.resolve(OWNER),
            (VALUE+"\n").getBytes(StandardCharsets.US_ASCII),
            StandardOpenOption.CREATE_NEW);
        final int[] count={0};
        final long[] total={0};
        Files.walkFileTree(template,new SimpleFileVisitor<Path>(){
            @Override public FileVisitResult preVisitDirectory(Path dir,
                    BasicFileAttributes attrs)throws IOException{
                Path rel=template.relativize(dir);
                if(!dir.equals(template)){
                    if(Files.isSymbolicLink(dir))
                        throw new IOException("P11_PREFIX_SOURCE_DIR_LINK");
                    Files.createDirectories(stage.resolve(rel));
                }
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file,
                    BasicFileAttributes attrs)throws IOException{
                if(++count[0]>MAX_ENTRIES)
                    throw new IOException("P11_PREFIX_FILES_LIMIT");
                Path rel=template.relativize(file);
                Path dest=stage.resolve(rel);
                if(Files.isSymbolicLink(file)){
                    if(!rel.equals(Path.of("dosdevices/c:"))
                        ||!Path.of("../drive_c").equals(Files.readSymbolicLink(file)))
                        throw new IOException("P11_PREFIX_FOREIGN_LINK");
                    Files.createSymbolicLink(dest,Path.of("../drive_c"));
                    return FileVisitResult.CONTINUE;
                }
                if(!attrs.isRegularFile()||attrs.size()<0)
                    throw new IOException("P11_PREFIX_SPECIAL_ENTRY");
                total[0]+=attrs.size();
                if(total[0]>MAX_BYTES)throw new IOException("P11_PREFIX_SIZE_LIMIT");
                Files.copy(file,dest,LinkOption.NOFOLLOW_LINKS);
                return FileVisitResult.CONTINUE;
            }
        });
        requireTree(stage,true);
        if(count[0]<4)throw new IOException("P11_PREFIX_COPY_INCOMPLETE");
        Files.move(stage,target,StandardCopyOption.ATOMIC_MOVE);
        return target;
    }
}
