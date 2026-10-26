package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Stage native Wine shell links as Winlator does; NEVER replace user files. */
public final class WineShellMenuBootstrap {
    private WineShellMenuBootstrap() {}

    private static Path profile(Path prefix) throws IOException {
        Path users=prefix.resolve("drive_c/users");
        if(!Files.isDirectory(users,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("WINE_USERS_DIR_MISSING");
        Path preferred=users.resolve("xuser");
        if(Files.isDirectory(preferred,LinkOption.NOFOLLOW_LINKS))
            return preferred;
        try(DirectoryStream<Path> profiles=Files.newDirectoryStream(users)) {
            for(Path path:profiles) {
                String name=path.getFileName().toString();
                if(!"Public".equalsIgnoreCase(name)
                        && !"Default".equalsIgnoreCase(name)
                        && Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))
                    return path;
            }
        }
        throw new IOException("WINE_USER_PROFILE_MISSING");
    }

    private static boolean link(Path dir,String title,String target) throws IOException {
        // Refuse path traversal through an existing symlink.
        Path parent=dir;
        while(parent!=null){
            if(Files.isSymbolicLink(parent))throw new IOException("SYMLINK_FOLDER_BLOCKED");
            parent=parent.getParent();
        }
        Files.createDirectories(dir);
        Path output=dir.resolve(title+".lnk");
        if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))return false;
        MSLink.Options options=new MSLink.Options();
        options.targetPath=target;
        options.iconLocation=target;
        MSLink.createFile(options,output.toFile());
        if(!Files.isRegularFile(output,LinkOption.NOFOLLOW_LINKS)
                ||Files.size(output)<=76)
            throw new IOException("WIN32_SHELL_LINK_WRITE_FAILED");
        return true;
    }

    public static String stage(RuntimeLayout layout) {
        try {
            if(!Files.isRegularFile(layout.winePrefixMarker(),LinkOption.NOFOLLOW_LINKS))
                return "RM11_V453_SHELL_MENU=PREFIX_NOT_READY";
            Path user=profile(layout.winePrefix);
            Path modern=user.resolve("AppData/Roaming/Microsoft/Windows/Start Menu/Programs");
            Path legacy=user.resolve("Start Menu/Programs");
            Path programs=Files.isDirectory(legacy,LinkOption.NOFOLLOW_LINKS)
                    &&!Files.isDirectory(modern,LinkOption.NOFOLLOW_LINKS)
                    ?legacy:modern;
            Path folder=programs.resolve("RM11 Tools");
            int created=0;
            if(link(folder,"Computer","C:\\windows\\system32\\winefile.exe"))created++;
            if(link(folder,"Notepad","C:\\windows\\notepad.exe"))created++;
            if(link(folder,"Command Prompt","C:\\windows\\system32\\cmd.exe"))created++;
            if(link(folder,"Registry Editor","C:\\windows\\regedit.exe"))created++;
            if(link(folder,"Wine Settings","C:\\windows\\system32\\winecfg.exe"))created++;
            if(link(user.resolve("Desktop"),"RM11 Computer",
                    "C:\\windows\\system32\\winefile.exe"))created++;
            return "RM11_V453_MENU_LINKS_CREATED="+created
                    +"\nRM11_V453_START_MENU="+programs;
        }catch(Exception e){
            return "RM11_V453_SHELL_MENU_STAGE_FAILED="
                    +e.getClass().getSimpleName()+": "+e.getMessage();
        }
    }
}
