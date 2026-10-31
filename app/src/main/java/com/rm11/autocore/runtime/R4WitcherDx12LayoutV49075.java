package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;

/** The Witcher 3 uses paths relative to bin/x64_dx12/witcher3.exe.
 * Copying its EXE flat to app files breaks ../../content and ../../dlc.
 * Build a PRIVATE mirrored directory structure using only symlinks back
 * to unchanged game assets. Never write into the original game root. */
public final class R4WitcherDx12LayoutV49075 {
    private R4WitcherDx12LayoutV49075(){}
    public static final class Paths {
        public final Path gameRoot,gameBin,originalExeDir,privateRoot,privateExeDir;
        public int privateEmptyDirsPruned=0;
        public boolean privateFolderShadowUsed=false;
        public boolean remastered50Detected=false;
        public int remasteredLegacyDirsExcluded=0;
        public long metadataSourceBytes=-1;
        public long metadataPrivateBytes=-1;
        Paths(Path gr,Path bin,Path exe,Path pr,String variant){
            gameRoot=gr;gameBin=bin;originalExeDir=exe;privateRoot=pr;
            privateExeDir=pr.resolve("bin").resolve(variant);
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
        return new Paths(root,bin,exeDir,privateRoot,"x64_dx12");
    }
    /** Classic DX11 is a different real EXE. It is used only if already
     * installed and explicitly validated; no DX12 binary is converted. */
    public static Paths planClassicDx11(Path original,Path privateRoot)throws IOException{
        if(original==null||privateRoot==null
            ||!R4WitcherExecutableV49072.classicDx11(original.toFile()))
            throw new IOException("NOT_A_WITCHER3_CLASSIC_DX11_EXE");
        Path exeDir=original.getParent(),bin=exeDir.getParent();
        if(bin==null||bin.getFileName()==null
                ||!"bin".equalsIgnoreCase(bin.getFileName().toString()))
            throw new IOException("WITCHER_BIN_LAYOUT_UNRECOGNIZED");
        Path root=bin.getParent();
        if(root==null)throw new IOException("WITCHER_ROOT_MISSING");
        return new Paths(root,bin,exeDir,privateRoot,"x64");
    }
    /**
     * Remastered v5.00 and 5.00c use content0 for their consolidated assets.
     * Exact upstream EXE sizes are intentional: never silently strip legitimate
     * content1..content12 or DLC from a classic/4.x installation.
     */
    public static boolean isKnownRemastered50Length(long bytes){
        return bytes==90832336L || bytes==90674640L;
    }
    public static boolean isRemastered50Layout(Path source,Path root)
            throws IOException{
        long bytes=Files.size(source);
        if(isKnownRemastered50Length(bytes))return true;
        // October 2026 hotfixes have new EXE hashes/sizes, but the 5.x
        // Steam depot is DX12-only and its binary is ~86.5 MiB. Restrict
        // heuristic detection to a DX12-only layout with a metadata store.
        // Older 4.x dual-DX11/DX12 installations remain unchanged.
        if(bytes<89500000L||bytes>91500000L)return false;
        Path classic=root.resolve("bin/x64/witcher3.exe");
        Path meta=root.resolve("content/metadata.store");
        Path consolidated=root.resolve("content/content0");
        return !Files.isRegularFile(classic,LinkOption.NOFOLLOW_LINKS)
            &&Files.isRegularFile(meta,LinkOption.NOFOLLOW_LINKS)
            &&!Files.isSymbolicLink(meta)
            &&safeDirectory(consolidated);
    }
    private static boolean obsoleteRemasteredContentFolder(String name){
        if(name==null||!name.matches("(?i)content[1-9][0-9]*"))return false;
        return true;
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
                boolean skipped=false;
                for(String excluded:skip.split(";"))
                    if(filename.equalsIgnoreCase(excluded))skipped=true;
                if(skipped)continue;
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
    /**
     * v49112: The Witcher 3 Remastered 5.0 can hang after D3D12 device
     * creation if obsolete empty content/dlc child folders are visible.
     * Never delete/mutate ANY original game folder. We only shadow a
     * suspicious tree in the app-private EXE sidecar, symlink regular
     * files to the unchanged original and omit empty nested directories.
     * Normal game layouts continue to use the historical directory symlink.
     */
    private static boolean containsEmptyNested(Path dir,int depth,int[] budget)
            throws IOException{
        if(++budget[0]>30000||depth>18)
            throw new IOException("WITCHER_FOLDER_SCAN_BUDGET_EXCEEDED");
        if(Files.isSymbolicLink(dir))throw new IOException("GAME_ASSET_SYMLINK_NOT_TRUSTED");
        if(!safeDirectory(dir))return false;
        boolean child=false;
        try(DirectoryStream<Path> entries=Files.newDirectoryStream(dir)){
            for(Path item:entries){
                child=true;
                if(Files.isSymbolicLink(item))
                    throw new IOException("GAME_ASSET_SYMLINK_NOT_TRUSTED");
                if(safeDirectory(item)
                    &&containsEmptyNested(item,depth+1,budget))return true;
            }
        }
        return depth>0&&!child;
    }
    private static int shadowWithoutEmptyDirectories(Path src,Path dst,
                             Path privateRoot,int depth,int[] budget,
                             Paths layout)throws IOException{
        if(++budget[0]>30000||depth>18)
            throw new IOException("WITCHER_PRIVATE_SHADOW_BUDGET_EXCEEDED");
        if(!safeDirectory(src))throw new IOException("GAME_ASSET_FOLDER_INVALID");
        ArrayList<Path> children=new ArrayList<>();
        try(DirectoryStream<Path> items=Files.newDirectoryStream(src)){
            for(Path child:items){
                if(Files.isSymbolicLink(child))
                    throw new IOException("GAME_ASSET_SYMLINK_NOT_TRUSTED");
                children.add(child);
            }
        }
        if(children.isEmpty()){
            if(depth==0)createPrivateDirectory(dst,privateRoot);
            return depth>0?1:0;
        }
        createPrivateDirectory(dst,privateRoot);
        int skipped=0,kept=0;
        for(Path child:children){
            // v49116: On VERIFIED 5.0 EXE layouts only, never present
            // old content1..contentN bundle trees to the new index builder.
            // They may be NONEMPTY, unlike the legacy empty-folder workaround.
            if(layout.remastered50Detected&&depth==0
                    &&src.getFileName()!=null
                    &&"content".equalsIgnoreCase(src.getFileName().toString())
                    &&safeDirectory(child)
                    &&obsoleteRemasteredContentFolder(
                        child.getFileName().toString())){
                layout.remasteredLegacyDirsExcluded++;
                skipped++;
                continue;
            }
            Path target=child.toRealPath();
            if(!target.getParent().equals(src.toRealPath()))
                throw new IOException("GAME_ASSET_CHILD_ESCAPES_ROOT");
            Path link=dst.resolve(child.getFileName());
            if(safeDirectory(child)){
                boolean empty;
                try(DirectoryStream<Path> sub=Files.newDirectoryStream(child)){
                    empty=!sub.iterator().hasNext();
                }
                if(empty){
                    // A previous app-private symlink at the same exact path
                    // is never followed or deleted; this is a new v49112
                    // stage and all hidden paths are app-private only.
                    skipped++;
                }else skipped+=shadowWithoutEmptyDirectories(
                    child,link,privateRoot,depth+1,budget,layout);
                if(Files.exists(link,LinkOption.NOFOLLOW_LINKS))kept++;
            }else if(Files.isRegularFile(child,LinkOption.NOFOLLOW_LINKS)){
                kept++;
                // v49114: Remastered 5.x may regenerate content/metadata.store.
                // A direct symlink would write through into the ORIGINAL
                // game directory. Give these mutable indexes app-private
                // copies, preserving both the original and prior local state.
                String filename=child.getFileName().toString();
                boolean contentRoot=depth==0&&src.getFileName()!=null
                    &&"content".equalsIgnoreCase(src.getFileName().toString());
                boolean mutableIndex=contentRoot
                    &&("metadata.store".equalsIgnoreCase(filename)
                       ||"metadata.store.stamp".equalsIgnoreCase(filename));
                if(mutableIndex){
                    if(Files.isSymbolicLink(link)){
                        if(!Files.readSymbolicLink(link).equals(target))
                            throw new IOException("PRIVATE_METADATA_LINK_MISMATCH");
                        Files.delete(link); // unlink app-private symlink only
                    }
                    if(!Files.exists(link,LinkOption.NOFOLLOW_LINKS))
                        Files.copy(child,link);
                    else if(!Files.isRegularFile(link,LinkOption.NOFOLLOW_LINKS))
                        throw new IOException("PRIVATE_METADATA_COLLISION");
                }else if(Files.isSymbolicLink(link)){
                    if(!Files.readSymbolicLink(link).equals(target))
                        throw new IOException("PRIVATE_ASSET_SYMLINK_MISMATCH");
                }else if(Files.exists(link,LinkOption.NOFOLLOW_LINKS))
                    throw new IOException("PRIVATE_ASSET_LINK_COLLISION");
                else Files.createSymbolicLink(link,target);
            }else throw new IOException("GAME_ASSET_UNEXPECTED_FILE_TYPE");
        }
        if(depth>0&&kept==0){
            // A legacy parent containing only empty descendant folders is
            // itself stale. Remove only our newly created private folder.
            Files.delete(dst);
            return skipped+1;
        }
        return skipped;
    }
    private static void stageAssetRoot(Paths layout,String name)throws IOException{
        // Remastered v5 has consolidated DLC in content/content0.
        // Exclude leftover pre-5.0 dlc trees even if they have files.
        // Never delete or rename the original folder.
        if(layout.remastered50Detected && "dlc".equalsIgnoreCase(name)){
            if(Files.exists(layout.gameRoot.resolve(name),LinkOption.NOFOLLOW_LINKS))
                layout.remasteredLegacyDirsExcluded++;
            return;
        }
        Path src=layout.gameRoot.resolve(name);
        if(!Files.exists(src,LinkOption.NOFOLLOW_LINKS))return;
        if(!safeDirectory(src))throw new IOException("GAME_ASSET_ROOT_INVALID");
        Path side=layout.privateRoot.resolve(name);
        boolean alreadyShadow=Files.isDirectory(side,LinkOption.NOFOLLOW_LINKS);
        boolean containsEmpty=containsEmptyNested(src,0,new int[1]);
        // Content indexes can be rewritten by the game. Always isolate the
        // content root, even when no obsolete empty directories exist.
        boolean requiresPrivateContent="content".equalsIgnoreCase(name);
        if(containsEmpty||alreadyShadow||requiresPrivateContent){
            if(Files.isSymbolicLink(side)){
                // Upgrading a previously linked app-private asset root is safe
                // only when its target is exactly this original game folder.
                // Delete the link itself, NEVER anything it points to.
                Path expected=src.toRealPath();
                if(!Files.readSymbolicLink(side).equals(expected))
                    throw new IOException("PRIVATE_ASSET_ROOT_MISMATCH");
                Files.delete(side);
            }
            layout.privateFolderShadowUsed=true;
            layout.privateEmptyDirsPruned+=shadowWithoutEmptyDirectories(
                src,side,layout.privateRoot,0,new int[1],layout);
        }else{
            Path target=src.toRealPath();
            if(Files.isSymbolicLink(side)){
                if(!Files.readSymbolicLink(side).equals(target))
                    throw new IOException("PRIVATE_ASSET_ROOT_MISMATCH");
            }else if(Files.exists(side,LinkOption.NOFOLLOW_LINKS))
                throw new IOException("PRIVATE_ASSET_ROOT_COLLISION");
            else Files.createSymbolicLink(side,target);
        }
    }

    /** Three levels: game root, bin, x64_dx12. Sidecar is hashed by source
     * path. Assets are linked read-only by policy, no game directories copied. */
    public static Paths mirror(Path original,Path privateRoot)throws IOException{
        return mirrorPlanned(original,plan(original,privateRoot));
    }
    /** v49089: DXVK sidecar for an existing DX11 EXE with correct
     * ../../content and ../../dlc relative paths. No game files touched. */
    public static Paths mirrorClassicDx11(Path original,Path privateRoot)throws IOException{
        return mirrorPlanned(original,planClassicDx11(original,privateRoot));
    }
    private static Paths mirrorPlanned(Path original,Paths layout)throws IOException{
        createPrivateDirectory(layout.privateRoot,layout.privateRoot);
        Path privateBin=layout.privateRoot.resolve("bin");
        createPrivateDirectory(privateBin,layout.privateRoot);
        createPrivateDirectory(layout.privateExeDir,layout.privateRoot);
        boolean dx12="x64_dx12".equalsIgnoreCase(
            layout.originalExeDir.getFileName().toString());
        if(dx12)layout.remastered50Detected=isRemastered50Layout(
            original,layout.gameRoot);
        // An affected 5.x game rebuilds metadata.store into a tiny 24-byte
        // index if old folders are visible; once damaged, startup cannot
        // recover. Refuse fake "success" rather than start with broken data.
        if(layout.remastered50Detected){
            Path sourceMeta=layout.gameRoot.resolve("content/metadata.store");
            layout.metadataSourceBytes=
                Files.isRegularFile(sourceMeta,LinkOption.NOFOLLOW_LINKS)
                &&!Files.isSymbolicLink(sourceMeta)
                ?Files.size(sourceMeta):-1;
            if(layout.metadataSourceBytes<4096L)
                throw new IOException("WITCHER_REMASTERED_SOURCE_METADATA_CORRUPTED_REPAIR_REQUIRED");
        }
        linkChildren(layout.gameRoot,layout.privateRoot,
            dx12?"bin;content;dlc":"bin",1600);
        if(dx12){
            stageAssetRoot(layout,"content");
            stageAssetRoot(layout,"dlc");
            if(layout.remastered50Detected){
                Path sourceMeta=layout.gameRoot.resolve("content/metadata.store");
                Path localMeta=layout.privateRoot.resolve("content/metadata.store");
                if(Files.isSymbolicLink(localMeta))
                    throw new IOException("WITCHER_PRIVATE_METADATA_UNEXPECTED_SYMLINK");
                layout.metadataPrivateBytes=Files.size(localMeta);
                // Repair only a damaged app-owned index with an intact
                // original; the source remains read-only to our code.
                if(layout.metadataPrivateBytes<4096L){
                    Files.copy(sourceMeta,localMeta,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    layout.metadataPrivateBytes=Files.size(localMeta);
                }
            }
        }
        linkChildren(layout.gameBin,privateBin,
            layout.originalExeDir.getFileName().toString(),1200);
        linkChildren(layout.originalExeDir,layout.privateExeDir,
            original.getFileName().toString(),1600);
        return layout;
    }
}
