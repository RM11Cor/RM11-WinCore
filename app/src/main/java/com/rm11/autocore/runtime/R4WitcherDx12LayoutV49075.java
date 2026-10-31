package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** The Witcher 3 uses paths relative to bin/x64_dx12/witcher3.exe.
 * Copying its EXE flat to app files breaks ../../content and ../../dlc.
 * Build a PRIVATE mirrored directory structure using only symlinks back
 * to unchanged game assets. Never write into the original game root. */
public final class R4WitcherDx12LayoutV49075 {
    private R4WitcherDx12LayoutV49075(){}
    public static final class Paths {
        public final Path gameRoot,gameBin,originalExeDir,privateRoot,privateExeDir;
        Paths(Path gr,Path bin,Path exe,Path pr){
            gameRoot=gr;gameBin=bin;originalExeDir=exe;privateRoot=pr;
            privateExeDir=pr.resolve("bin").resolve("x64_dx12");
        }
        public Path localExe(){return privateExeDir.resolve("witcher3.exe");}
        public Path localContent(){return privateExeDir.resolve("../../content").normalize();}
    }
    public static Paths plan(Path original,Path privateRoot)throws IOException {
        if(original==null||privateRoot==null
            ||!R4Vkd3dV49073.isWitcherDx12(original))
            throw new IOException("NOT_A_WITCHER3_DX12_EXE");
        Path exeDir=original.getParent();
        Path bin=exeDir.getParent();
        if(bin==null||bin.getFileName()==null
            ||!"bin".equalsIgnoreCase(bin.getFileName().toString()))
            throw new IOException("WITCHER_BIN_LAYOUT_UNRECOGNIZED");
        Path root=bin.getParent();
        if(root==null)throw new IOException("WITCHER_ROOT_MISSING");
        if(!root.toAbsolutePath().normalize().startsWith(root.getRoot()))
            throw new IOException("INVALID_ROOT");
        return new Paths(root,bin,exeDir,privateRoot);
    }
    private static boolean safeDirectory(Path path){
        return Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS)
            &&!Files.isSymbolicLink(path);
    }
    private static void createPrivateDirectory(Path dir,Path privateRoot)
            throws IOException{
        if(Files.isSymbolicLink(privateRoot)||Files.isSymbolicLink(dir))
            throw new IOException("PRIVATE_SIDE_CAR_DIRECTORY_SYMLINK");
        Files.createDirectories(dir);
        if(!dir.toRealPath().startsWith(privateRoot.toRealPath()))
            throw new IOException("PRIVATE_SIDE_CAR_ESCAPE");
    }
    private static int linkChildren(Path original,Path privateDir,
                                     String skip,int limit)throws IOException{
        if(!safeDirectory(original))throw new IOException("ORIGINAL_FOLDER_MISSING");
        int count=0;
        Path trusted=original.toRealPath();
        try(DirectoryStream<Path> entries=Files.newDirectoryStream(original)){
            for(Path child:entries){
                if(++count>limit)throw new IOException("WITCHER_DIRECTORY_TOO_MANY_ENTRIES");
                String filename=child.getFileName().toString();
                if(filename.equalsIgnoreCase(skip))continue;
                if(Files.isSymbolicLink(child))
                    throw new IOException("ORIGINAL_SYMLINK_NOT_TRUSTED");
                Path destination=privateDir.resolve(filename);
                Path target=child.toRealPath();
                if(!target.getParent().equals(trusted))
                    throw new IOException("ORIGINAL_CHILD_ESCAPE");
                if(Files.isSymbolicLink(destination)){
                    if(!Files.readSymbolicLink(destination).equals(target))
                        throw new IOException("STALE_PRIVATE_SYMLINK_"+filename);
                }else if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS)){
                    throw new IOException("PRIVATE_SIDECAR_COLLISION_"+filename);
                }else Files.createSymbolicLink(destination,target);
            }
        }
        return count;
    }
    /** Three levels: game root, bin, x64_dx12. Sidecar is hashed by source
     * path. Assets are linked read-only by policy, no game directories copied. */
    public static Paths mirror(Path original,Path privateRoot)throws IOException{
        Paths layout=plan(original,privateRoot);
        createPrivateDirectory(layout.privateRoot,layout.privateRoot);
        Path privateBin=layout.privateRoot.resolve("bin");
        createPrivateDirectory(privateBin,layout.privateRoot);
        createPrivateDirectory(layout.privateExeDir,layout.privateRoot);
        linkChildren(layout.gameRoot,layout.privateRoot,"bin",1600);
        linkChildren(layout.gameBin,privateBin,"x64_dx12",1200);
        linkChildren(layout.originalExeDir,layout.privateExeDir,
            original.getFileName().toString(),1600);
        return layout;
    }
}
