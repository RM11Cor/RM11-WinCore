package com.rm11.autocore.runtime;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * RM11 Nova Shell safe operations. Real filesystem actions are deliberately
 * limited to a private Nova Workspace to protect Wine and game data.
 * Copy *from* existing app-private files is allowed; mutation of Wine runtime
 * and C:/Windows is NOT. No implicit overwrite or recursive delete.
 */
public final class NovaWorkspaceFiles {
    private static final long MAX_COPY_SIZE=256L*1024*1024;
    private final Path home;
    private final Path workspace;

    public NovaWorkspaceFiles(File appFiles) throws IOException {
        home=appFiles.getCanonicalFile().toPath();
        if (!Files.isDirectory(home,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_HOME_UNAVAILABLE");
        workspace=home.resolve("nova-workspace");
        if (Files.exists(workspace,LinkOption.NOFOLLOW_LINKS)
                && Files.isSymbolicLink(workspace))
            throw new IOException("RM11_NOVA_WORKSPACE_SYMLINK_BLOCKED");
        Files.createDirectories(workspace);
        if (!Files.isDirectory(workspace,LinkOption.NOFOLLOW_LINKS)
                || !workspace.toRealPath().equals(workspace.toAbsolutePath().normalize()))
            throw new IOException("RM11_NOVA_WORKSPACE_NOT_PLAIN_DIRECTORY");
    }
    public File directory(){return workspace.toFile();}

    private Path verified(Path path,boolean insideWorkspace,boolean requireExisting)
            throws IOException {
        Path abs=path.toAbsolutePath().normalize();
        Path real=abs.toFile().getCanonicalFile().toPath();
        Path boundary=insideWorkspace?workspace:home;
        if ((!real.equals(boundary) && !real.startsWith(boundary))
            || (insideWorkspace && real.equals(boundary) && !Files.isDirectory(real))
            || Files.isSymbolicLink(abs))
            throw new IOException("RM11_NOVA_PATH_OUT_OF_BOUNDS_OR_SYMLINK");
        if (requireExisting && !Files.exists(abs,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_ITEM_MISSING");
        return abs;
    }
    private Path editableChild(Path path) throws IOException {
        Path real=verified(path,true,false);
        if(real.equals(workspace))throw new IOException("RM11_NOVA_ROOT_PROTECTED");
        return real;
    }
    public boolean canEdit(File file) {
        try { return !verified(file.toPath(),true,false).equals(workspace); }
        catch(IOException ex){return false;}
    }
    private String filename(String name) throws IOException {
        if(name==null||name.trim().isEmpty()||name.equals(".")||name.equals("..")
                ||name.indexOf('/')>=0||name.indexOf('\\')>=0||name.indexOf('\0')>=0
                ||name.length()>180)
            throw new IOException("RM11_NOVA_INVALID_FILENAME");
        return name;
    }
    private Path freeDestination(Path dir,String name)throws IOException {
        Path parent=verified(dir,true,true);
        if(!Files.isDirectory(parent,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_DESTINATION_NOT_DIRECTORY");
        Path dest=editableChild(parent.resolve(filename(name)));
        if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_DESTINATION_EXISTS");
        return dest;
    }
    public File createFolder(File folder,String name)throws IOException {
        return Files.createDirectory(freeDestination(folder.toPath(),name)).toFile();
    }
    public File createFile(File folder,String name)throws IOException {
        return Files.createFile(freeDestination(folder.toPath(),name)).toFile();
    }
    public File rename(File original,String name)throws IOException {
        Path from=editableChild(original.toPath());
        if(!Files.exists(from,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_ITEM_MISSING");
        Path to=freeDestination(from.getParent(),name);
        return Files.move(from,to).toFile();
    }
    public void delete(File original)throws IOException {
        Path from=editableChild(original.toPath());
        // Only files or EMPTY folders. Never recursive-delete games or saves.
        Files.delete(from);
    }
    public File copyFile(File original,File folder)throws IOException {
        Path from=verified(original.toPath(),false,true);
        if(!Files.isRegularFile(from,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_COPY_FILES_ONLY");
        if(Files.size(from)>MAX_COPY_SIZE)
            throw new IOException("RM11_NOVA_COPY_OVER_256MB_DISABLED");
        Path to=freeDestination(folder.toPath(),from.getFileName().toString());
        return Files.copy(from,to,LinkOption.NOFOLLOW_LINKS).toFile();
    }
    /**
     * Import a readable single file from a separately authorized Android D:
     * drive. This reads only (never changes the source) and still writes only
     * into Nova Workspace under the existing 256 MB and no-overwrite rules.
     */
    public File copyFromPhone(File original,File folder,File authorizedPhoneRoot)
            throws IOException {
        if(original==null||authorizedPhoneRoot==null
                ||Files.isSymbolicLink(original.toPath()))
            throw new IOException("Invalid Android phone file");
        Path base=authorizedPhoneRoot.getCanonicalFile().toPath();
        Path source=original.toPath().toRealPath();
        if(!source.startsWith(base)
                ||!Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Phone file is outside authorized D:");
        if(Files.size(source)>MAX_COPY_SIZE)
            throw new IOException("RM11_NOVA_COPY_OVER_256MB_DISABLED");
        Path target=freeDestination(folder.toPath(),source.getFileName().toString());
        return Files.copy(source,target,LinkOption.NOFOLLOW_LINKS).toFile();
    }
    public File moveFile(File original,File folder)throws IOException {
        Path from=editableChild(original.toPath());
        if(!Files.isRegularFile(from,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RM11_NOVA_MOVE_FILES_ONLY");
        Path to=freeDestination(folder.toPath(),from.getFileName().toString());
        return Files.move(from,to).toFile();
    }
}
