package com.rm11.autocore.runtime;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Portable on-disk Nova desktop launcher pointing to a user-selected EXE.
 * Shortcut metadata is not itself executable. Every launch validates the
 * underlying PE file and its source location again.
 */
public final class NovaDesktopShortcut {
    public static final String EXT=".rm11link";
    private static final String MARKER="RM11_NOVA_SHORTCUT_V1";
    private NovaDesktopShortcut(){}
    public static File create(NovaWorkspaceFiles fs, File desktop,File exe)
            throws IOException {
        if(!desktop.isDirectory()||!fs.canEdit(new File(desktop,".probe")))
            throw new IOException("Shortcut destination must be Nova Desktop");
        if(exe==null||!exe.isFile())throw new IOException("Missing EXE");
        String base=exe.getName();
        if(base.toLowerCase(java.util.Locale.ROOT).endsWith(".exe"))
            base=base.substring(0,base.length()-4);
        base=base.replaceAll("[^a-zA-Z0-9 _()\\-.]","_").trim();
        if(base.isEmpty())base="Windows program";
        if(base.length()>90)base=base.substring(0,90);
        int index=0;
        File saved;
        do{
            String name=base+(index==0?"":" ("+index+")")+EXT;
            saved=new File(desktop,name);
            index++;
        }while(saved.exists()&&index<200);
        if(saved.exists())throw new IOException("Shortcut name count exceeded");
        File staged=fs.createFile(desktop,saved.getName());
        boolean ok=false;
        try {
            Files.write(staged.toPath(),(MARKER+"\n"+exe.getCanonicalPath()+"\n")
                    .getBytes(StandardCharsets.UTF_8));
            ok=true;return staged;
        }finally{if(!ok)Files.deleteIfExists(staged.toPath());}
    }
    public static boolean isShortcut(File file){
        return file!=null&&file.isFile()&&
                file.getName().toLowerCase(java.util.Locale.ROOT).endsWith(EXT);
    }
    public static File resolve(File file)throws IOException {
        if(!isShortcut(file)||Files.isSymbolicLink(file.toPath()))
            throw new IOException("Not a regular Nova shortcut");
        if(Files.size(file.toPath())>10000)
            throw new IOException("Unexpected oversized shortcut");
        List<String> lines=Files.readAllLines(file.toPath(),StandardCharsets.UTF_8);
        if(lines.size()<2||!MARKER.equals(lines.get(0))||lines.get(1).length()>8192)
            throw new IOException("Invalid Nova shortcut data");
        Path dest=new File(lines.get(1)).toPath();
        if(!dest.isAbsolute()||Files.isSymbolicLink(dest))
            throw new IOException("Untrusted shortcut target");
        return dest.toFile();
    }
}
