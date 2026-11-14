package com.r4.carxpc;

import java.io.BufferedInputStream;
import java.io.DigestInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystemException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

/**
 * R3C18. Streaming, source-pinned Linux x86_64 Wine rootfs installer.
 *
 * No root, Wine execution, FEX configuration, shell commands, or filesystem
 * privileged operations. The archive is NOT bundled inside the APK.
 * This class builds an owned data-only guest rootfs. Android 10+ execution
 * restrictions and guest process emulation are intentionally NOT bypassed.
 */
public final class GuestRootfsInstaller {
    public static final String ARCHIVE_SHA256 =
        "86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0";
    public static final String ROOTFS_NAME = "wine-guest-x86_64";
    private static final int BLOCK = 512;
    private static final int MAX_ENTRIES = 200000;
    private static final long MAX_UNPACKED = 8L * 1024 * 1024 * 1024;
    private static final long MAX_PAX = 1024L * 1024;
    private static final String[] REQUIRED = {
        "usr/share/wine/wine.inf",
        "usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll",
        "usr/lib/wine/wine64",
        "tmp/kernix-real-win32-smoke.exe"
    };

    private GuestRootfsInstaller() {}

    public static final class Receipt {
        public final String sha256;
        public final int entries;
        public final long regularBytes;
        public final int symlinks;
        public final int hardlinks;
        public final Path root;
        private Receipt(String hash,int count,long bytes,int links,int hard,Path p) {
            sha256=hash;entries=count;regularBytes=bytes;symlinks=links;hardlinks=hard;root=p;
        }
    }
    private static final class Link {
        final String path, target;
        final boolean hard;
        Link(String p,String t,boolean h) {path=p;target=t;hard=h;}
    }
    private static final class Counts {
        int entries=0,symlinks=0,hardlinks=0;
        long expanded=0;
        final List<Link> links=new ArrayList<>();
        final Set<String> seen=new HashSet<>();
        final Set<String> files=new HashSet<>();
    }

    /**
     * Caller provides a stream from Android's Storage Access Framework and an
     * app-owned filesDir. Caller must not provide a shared-storage target.
     */
    public static Receipt install(InputStream archive, Path appFilesDir)
            throws IOException {
        if(archive==null || appFilesDir==null) throw new IOException("NULL_ARGUMENT");
        Path parent=appFilesDir.toAbsolutePath().normalize();
        if(!Files.isDirectory(parent,LinkOption.NOFOLLOW_LINKS) ||
           Files.isSymbolicLink(parent)) throw new IOException("UNOWNED_OR_INVALID_APP_DIR");
        // Caller is responsible for choosing Android Context.getFilesDir().
        Path stage=parent.resolve("."+ROOTFS_NAME+"-stage-"+UUID.randomUUID());
        Path destination=parent.resolve(ROOTFS_NAME);
        Path backup=parent.resolve("."+ROOTFS_NAME+"-previous-"+UUID.randomUUID());
        Files.createDirectory(stage);
        boolean oldMoved=false, committed=false;
        try {
            Counts counts=new Counts();
            MessageDigest sha256=digest();
            // Digest the compressed artifact bytes, not reconstructed TAR.
            DigestInputStream digestIn=new DigestInputStream(archive,sha256);
            try (GZIPInputStream gz=new GZIPInputStream(
                    new BufferedInputStream(digestIn,65536),65536)) {
                unpack(gz,stage,counts);
            }
            String hash=hex(sha256.digest());
            if(!ARCHIVE_SHA256.equals(hash)) throw new IOException("ARCHIVE_SHA256_MISMATCH");
            for(String path:REQUIRED) {
                if(!counts.files.contains(path) || !Files.isRegularFile(
                        stage.resolve(path),LinkOption.NOFOLLOW_LINKS))
                    throw new IOException("MISSING_REQUIRED_GUEST_FILE:"+path);
            }
            // Rootfs layout has no outside-the-archive link targets. Linux
            // absolute guest links are rewritten to stage-relative targets.
            createLinks(stage,counts);

            // Trusted manifest belongs to app-owned staging; created after
            // archive SHA matches. Keep receipt separate from guest archive.
            Files.write(stage.resolve(".r4-rootfs-receipt"),(
                "schema=r4.carx.r3c18.owned-linux-x64-rootfs.v1\n"+
                "source_archive_sha256="+hash+"\n"+
                "entries="+counts.entries+"\n"+
                "regular_bytes="+counts.expanded+"\n"+
                "symlinks="+counts.symlinks+"\n"+
                "hardlinks="+counts.hardlinks+"\n").getBytes(StandardCharsets.UTF_8));

            if(Files.exists(destination,LinkOption.NOFOLLOW_LINKS)) {
                if(!Files.isDirectory(destination,LinkOption.NOFOLLOW_LINKS) ||
                    Files.isSymbolicLink(destination))
                    throw new IOException("INVALID_EXISTING_ROOTFS");
                move(destination,backup);
                oldMoved=true;
            }
            try {
                move(stage,destination);
                committed=true;
            } catch(IOException e) {
                if(oldMoved) {
                    try { move(backup,destination); oldMoved=false; }
                    catch(IOException failure) { e.addSuppressed(failure); }
                }
                throw e;
            }
            if(oldMoved) {
                deleteTree(backup);
                oldMoved=false;
            }
            return new Receipt(hash,counts.entries,counts.expanded,
                               counts.symlinks,counts.hardlinks,destination);
        } finally {
            if(!committed) {
                deleteTree(stage);
                if(oldMoved && !Files.exists(destination,LinkOption.NOFOLLOW_LINKS)) {
                    move(backup,destination);
                }
            }
        }
    }

    private static void unpack(InputStream in,Path stage,Counts c)
            throws IOException {
        byte[] header=new byte[BLOCK];
        String longName=null,longLink=null;
        Map<String,String> pax=new HashMap<>();
        int zeroBlocks=0;
        while(true) {
            if(!readFully(in,header)) throw new IOException("TAR_EOF_BEFORE_END");
            if(allZero(header)) {
                ++zeroBlocks;
                if(zeroBlocks>=2) {
                    // Must consume the entire gzip stream for checksum/digest.
                    byte[] tail=new byte[8192];int n;
                    while((n=in.read(tail))!=-1) for(int i=0;i<n;i++)
                        if(tail[i]!=0)throw new IOException("TRAILING_NONZERO_TAR_BYTES");
                    return;
                }
                continue;
            }
            if(zeroBlocks>0)throw new IOException("BROKEN_TAR_END_BLOCKS");
            validateHeader(header);
            int type=header[156] & 255;
            long size=octal(header,124,12);
            int mode=(int)octal(header,100,8);
            if(size<0 || size>MAX_UNPACKED ||
               c.expanded>MAX_UNPACKED-size) throw new IOException("TAR_SIZE_LIMIT");
            String name=field(header,0,100);
            String prefix=field(header,345,155);
            if(!prefix.isEmpty()) name=prefix+"/"+name;
            String target=field(header,157,100);

            if(type=='x'||type=='g'||type=='L'||type=='K') {
                if(size>MAX_PAX)throw new IOException("TAR_EXTENDED_HEADER_TOO_LARGE");
                byte[] bytes=readArray(in,(int)size);
                skipPadding(in,size);
                if(type=='L') longName=trimNul(bytes);
                else if(type=='K') longLink=trimNul(bytes);
                else if(type=='x')pax.putAll(readPax(bytes));
                // Never obey global PAX size/path overrides silently:
                // changes must be per-entry and size remains header-owned.
                else if(type=='g') {
                    Map<String,String> global=readPax(bytes);
                    if(global.containsKey("path")||global.containsKey("linkpath") ||
                       global.containsKey("size"))
                        throw new IOException("UNSAFE_GLOBAL_PAX_OVERRIDE");
                }
                continue;
            }
            if(longName!=null){name=longName;longName=null;}
            if(longLink!=null){target=longLink;longLink=null;}
            if(pax.containsKey("path"))name=pax.get("path");
            if(pax.containsKey("linkpath"))target=pax.get("linkpath");
            if(pax.containsKey("size") && !pax.get("size").equals(Long.toString(size)))
                throw new IOException("UNSUPPORTED_PAX_SIZE_OVERRIDE");
            pax.clear();
            String safe=guestPath(name);
            if(safe.isEmpty()) {
                if(type!='5')throw new IOException("NON_DIRECTORY_ROOT_ENTRY");
                drain(in,size);
                skipPadding(in,size);
                continue;
            }
            if(++c.entries>MAX_ENTRIES) throw new IOException("TOO_MANY_ENTRIES");
            Path path=stage.resolve(safe);
            if(!path.normalize().startsWith(stage)) throw new IOException("PATH_ESCAPE");
            switch(type) {
                case 0: case '0': case '7': // regular, GNU contiguous
                    if(!c.seen.add(safe))throw new IOException("DUPLICATE_FILE");
                    Files.createDirectories(path.getParent());
                    if(Files.exists(path,LinkOption.NOFOLLOW_LINKS))
                        throw new IOException("ARCHIVE_FILE_COLLISION");
                    try(OutputStream o=Files.newOutputStream(path)) {
                        copy(in,o,size);
                    }
                    path.toFile().setReadable(true,true);
                    path.toFile().setWritable(true,true);
                    if((mode & 0111)!=0)path.toFile().setExecutable(true,true);
                    c.files.add(safe);
                    c.expanded+=size;
                    break;
                case '5':
                    if(!c.seen.add(safe) && !Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))
                        throw new IOException("DUPLICATE_TYPE_CONFLICT");
                    Files.createDirectories(path);
                    if(!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))
                        throw new IOException("DIRECTORY_TYPE_CONFLICT");
                    drain(in,size);
                    break;
                case '1': case '2':
                    if(!c.seen.add(safe))throw new IOException("DUPLICATE_LINK");
                    c.links.add(new Link(safe,target,type=='1'));
                    if(type=='1')c.hardlinks++;else c.symlinks++;
                    drain(in,size);
                    break;
                case '3': case '4': case '6':
                    // Linux dev nodes/FIFOs cannot be built in unprivileged
                    // Android app storage and must never be substituted with
                    // a fake regular device. The future FEX guest /dev bridge
                    // is a separate explicit implementation gate.
                    if(!safe.startsWith("dev/"))throw new IOException("SPECIAL_FILE_OUTSIDE_DEV");
                    drain(in,size);
                    break;
                default: throw new IOException("UNSUPPORTED_TAR_ENTRY_TYPE:"+type);
            }
            skipPadding(in,size);
        }
    }

    private static void createLinks(Path stage,Counts c) throws IOException {
        // Hardlinks are materialized BEFORE symbolic links; no symlink can
        // influence paths created by archive extraction.
        for(Link l:c.links)if(l.hard) {
            Path target=stage.resolve(guestPath(l.target));
            if(!target.normalize().startsWith(stage) ||
               !Files.isRegularFile(target,LinkOption.NOFOLLOW_LINKS))
                throw new IOException("UNSAFE_OR_MISSING_HARDLINK_TARGET");
            Path link=stage.resolve(l.path);
            Files.createDirectories(link.getParent());
            if(Files.exists(link,LinkOption.NOFOLLOW_LINKS))
                throw new IOException("HARDLINK_COLLISION");
            Files.createLink(link,target);
            c.files.add(l.path);
        }
        for(Link l:c.links)if(!l.hard) {
            if(l.target==null||l.target.isEmpty() ||
               l.target.indexOf('\\')>=0 || l.target.indexOf('\0')>=0)
                throw new IOException("BAD_SYMLINK_TARGET");
            Path link=stage.resolve(l.path);
            Files.createDirectories(link.getParent());
            if(Files.exists(link,LinkOption.NOFOLLOW_LINKS))
                throw new IOException("SYMLINK_COLLISION");
            Path relParent=stage.relativize(link.getParent());
            String raw=l.target;
            // Absolute Linux guest paths are not host paths. Rewrite them
            // into a relative target anchored at guest root.
            Path target=raw.startsWith("/") ?
                stage.resolve(guestPath(raw.substring(1))) :
                stage.resolve(relParent).resolve(raw).normalize();
            if(!target.normalize().startsWith(stage))
                throw new IOException("SYMLINK_ESCAPE:"+l.path);
            Path guestRelative=link.getParent().relativize(target.normalize());
            Files.createSymbolicLink(link,guestRelative);
        }
    }

    private static String guestPath(String s) throws IOException {
        if(s==null)throw new IOException("NULL_TAR_PATH");
        while(s.startsWith("./"))s=s.substring(2);
        while(s.endsWith("/")&&!s.isEmpty())s=s.substring(0,s.length()-1);
        if(s.equals(".")||s.isEmpty())return "";
        if(s.startsWith("/")||s.indexOf('\\')>=0||s.indexOf('\0')>=0 ||
           s.contains("//")||s.length()>4096)throw new IOException("UNSAFE_TAR_PATH");
        String[] parts=s.split("/",-1);
        for(String p:parts)
            if(p.isEmpty()||p.equals(".")||p.equals("..")||p.length()>255 ||
               p.indexOf('\r')>=0||p.indexOf('\n')>=0)
                throw new IOException("PATH_COMPONENT_REJECTED");
        return s;
    }
    private static void validateHeader(byte[] h) throws IOException {
        long stored=octal(h,148,8),sum=0;
        for(int i=0;i<BLOCK;i++)
            sum+=(i>=148&&i<156)?32:(h[i]&255);
        if(sum!=stored) throw new IOException("TAR_HEADER_CHECKSUM_BAD");
        String magic=field(h,257,6);
        if(!magic.startsWith("ustar"))
            throw new IOException("TAR_MAGIC_NOT_USTAR");
    }
    private static String field(byte[] b,int pos,int n) {
        int end=pos;
        while(end<pos+n&&b[end]!=0)end++;
        return new String(b,pos,end-pos,StandardCharsets.UTF_8);
    }
    private static long octal(byte[] h,int pos,int n) throws IOException {
        int end=pos+n,i=pos;
        while(i<end&&(h[i]==' '||h[i]==0))i++;
        if(i<end&&(h[i]&0x80)!=0)
            throw new IOException("BASE256_TAR_VALUE_UNSUPPORTED");
        long v=0;
        for(;i<end;i++) {
            int c=h[i]&255;
            if(c==0||c==' ')break;
            if(c<'0'||c>'7')throw new IOException("INVALID_TAR_OCTAL");
            if(v>Long.MAX_VALUE/8)throw new IOException("OCTAL_OVERFLOW");
            v=v*8+(c-'0');
        }
        return v;
    }
    private static Map<String,String> readPax(byte[] b)throws IOException {
        Map<String,String> m=new HashMap<>();
        String text=new String(b,StandardCharsets.UTF_8);
        int idx=0;
        while(idx<text.length()) {
            int gap=text.indexOf(' ',idx);
            if(gap<idx)throw new IOException("PAX_LENGTH_MISSING");
            int length;
            try {length=Integer.parseInt(text.substring(idx,gap));}
            catch(NumberFormatException e){throw new IOException("PAX_LENGTH_INVALID",e);}
            if(length<=0||idx+length>text.length())throw new IOException("PAX_RECORD_OOB");
            String record=text.substring(gap+1,idx+length);
            if(!record.endsWith("\n"))throw new IOException("PAX_RECORD_NEWLINE");
            int equals=record.indexOf('=');
            if(equals<1)throw new IOException("PAX_RECORD_KEY_MISSING");
            m.put(record.substring(0,equals),record.substring(equals+1,record.length()-1));
            idx+=length;
        }
        return m;
    }
    private static String trimNul(byte[] a) {
        int end=0;while(end<a.length&&a[end]!=0&&a[end]!='\n')end++;
        return new String(a,0,end,StandardCharsets.UTF_8);
    }
    private static boolean allZero(byte[] a) {
        for(byte b:a)if(b!=0)return false;
        return true;
    }
    private static boolean readFully(InputStream in,byte[] bytes)throws IOException {
        int off=0,n;
        while(off<bytes.length) {
            n=in.read(bytes,off,bytes.length-off);
            if(n<0) {
                if(off==0)return false;
                throw new IOException("PARTIAL_TAR_BLOCK");
            }
            if(n==0)continue;
            off+=n;
        }
        return true;
    }
    private static byte[] readArray(InputStream in,int n)throws IOException {
        byte[] a=new byte[n];if(!readFully(in,a))throw new IOException("TRUNCATED_TAR_PAX");
        return a;
    }
    private static void copy(InputStream in,OutputStream out,long len)throws IOException {
        byte[] b=new byte[65536];
        while(len>0) {
            int n=in.read(b,0,(int)Math.min(len,b.length));
            if(n<0)throw new IOException("TRUNCATED_FILE_PAYLOAD");
            if(n==0)continue;
            if(out!=null)out.write(b,0,n);
            len-=n;
        }
    }
    private static void drain(InputStream in,long len)throws IOException {copy(in,null,len);}
    private static void skipPadding(InputStream in,long len)throws IOException {
        long pad=(BLOCK-(len%BLOCK))%BLOCK;
        drain(in,pad);
    }
    private static MessageDigest digest() {
        try{return MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
    private static String hex(byte[] bytes) {
        StringBuilder s=new StringBuilder(bytes.length*2);
        for(byte b:bytes)s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    private static void move(Path a,Path b)throws IOException {
        try{Files.move(a,b,StandardCopyOption.ATOMIC_MOVE);}
        catch(AtomicMoveNotSupportedException e){Files.move(a,b);}
    }
    private static void deleteTree(Path path)throws IOException {
        if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS))return;
        // The tree can contain intentionally created guest symlinks. Never
        // follow them when cleaning a failed staging directory.
        try(java.util.stream.Stream<Path> stream=Files.walk(path)) {
            List<Path> paths=new ArrayList<>();
            stream.forEach(paths::add);
            for(int i=paths.size()-1;i>=0;i--)
                Files.deleteIfExists(paths.get(i));
        }
    }
}
