package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** App-local EXE browser: always begin at the Android primary storage root.
 * Unlike ACTION_OPEN_DOCUMENT, this does not resume the last picked folder.
 * Path listing is read-only. No game copying or directory relocation. */
public final class R4PrimaryExePathV49076 {
    private R4PrimaryExePathV49076(){}
    public static final class Entry {
        public final Path path;
        public final boolean directory;
        Entry(Path p,boolean folder){path=p;directory=folder;}
    }
    private static Path realRoot(Path root)throws IOException{
        if(root==null || Files.isSymbolicLink(root))
            throw new IOException("INVALID_PRIMARY_STORAGE_ROOT");
        Path actual=root.toRealPath();
        if(!Files.isDirectory(actual)||!Files.isReadable(actual))
            throw new IOException("PRIMARY_STORAGE_UNREADABLE");
        return actual;
    }
    private static Path within(Path root,Path path)throws IOException{
        Path base=realRoot(root);
        if(path==null || Files.isSymbolicLink(path))
            throw new IOException("STORAGE_ITEM_SYMLINK_OR_MISSING");
        Path actual=path.toRealPath();
        if(!actual.startsWith(base))
            throw new IOException("STORAGE_ITEM_OUTSIDE_PRIMARY_ROOT");
        return actual;
    }
    public static Path root(Path source)throws IOException{return realRoot(source);}
    public static boolean validExe(Path root,Path file){
        try {
            Path p=within(root,file);
            String name=p.getFileName().toString().toLowerCase(Locale.ROOT);
            return name.endsWith(".exe")&&name.length()>4
                &&Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)
                &&Files.isReadable(p)&&Files.size(p)>64;
        }catch(Exception ignored){return false;}
    }
    public static Path parent(Path root,Path dir)throws IOException{
        Path base=realRoot(root),current=within(root,dir);
        if(current.equals(base))return base;
        Path up=current.getParent();
        if(up==null || !up.startsWith(base))return base;
        return up;
    }
    /** Only files EXE and real directories; no hidden browsing escape via
     * symlinks. A per-folder cap prevents very large Android UI allocations. */
    public static List<Entry> entries(Path root,Path current)throws IOException {
        Path base=realRoot(root),folder=within(root,current);
        if(!folder.startsWith(base)||!Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS)
            ||!Files.isReadable(folder))
            throw new IOException("GAME_FOLDER_NOT_READABLE");
        List<Entry> entries=new ArrayList<>();
        int visited=0;
        try(DirectoryStream<Path> children=Files.newDirectoryStream(folder)){
            for(Path child:children){
                if(++visited>12000)throw new IOException("GAME_FOLDER_TOO_MANY_FILES");
                if(Files.isSymbolicLink(child))continue;
                if(Files.isDirectory(child,LinkOption.NOFOLLOW_LINKS)){
                    entries.add(new Entry(child,true));
                }else if(validExe(base,child)){
                    entries.add(new Entry(child,false));
                }
                if(entries.size()>2200)throw new IOException("GAME_FOLDER_TOO_MANY_VISIBLE_ITEMS");
            }
        }
        entries.sort(Comparator.comparing((Entry e)->!e.directory)
            .thenComparing(e->e.path.getFileName().toString(),String.CASE_INSENSITIVE_ORDER));
        return entries;
    }
    /** Read-only source-folder evidence, not a claim that the game runs. */
    public static String sourceEvidence(Path root,Path exe) {
        try {
            Path base=realRoot(root),file=within(root,exe);
            if(!validExe(base,file))return "R4_V49076_SOURCE_EXE=INVALID";
            Path folder=file.getParent();
            boolean folderReadable=Files.isDirectory(folder,LinkOption.NOFOLLOW_LINKS)
                &&Files.isReadable(folder);
            int siblings=0,dirs=0;
            try(DirectoryStream<Path> files=Files.newDirectoryStream(folder)){
                for(Path p:files) {
                    if(++siblings>=2500)break;
                    if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))dirs++;
                }
            }
            return "R4_V49076_SOURCE_EXE=VALID\n"
                +"R4_V49076_SOURCE_FOLDER_READABLE="+folderReadable+"\n"
                +"R4_V49076_SOURCE_FOLDER_ENTRIES_UP_TO_2500="+siblings+"\n"
                +"R4_V49076_SOURCE_FOLDER_DIRECTORIES_UP_TO_2500="+dirs+"\n"
                +"R4_V49076_LIBRARY_PERSISTS_FULL_CANONICAL_EXE_PATH=true\n"
                +"R4_V49076_GAME_FILES_COPIED_ON_IMPORT=false\n"
                +"R4_V49076_GAME_FILES_MODIFIED=false\n";
        }catch(Exception e){
            return "R4_V49076_SOURCE_AUDIT_ERROR="+e.getClass().getSimpleName();
        }
    }
}
