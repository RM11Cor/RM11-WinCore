package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * v49121: independently installs the complete matching Proton ARM64EC / FEX
 * 2610 runtime into a new app-private slot. Native loader, NTDLL, WineServer
 * and FEX UnixLib ELF counterparts must come from this exact APK and match
 * source-attested SHA-256. No root, no user-game file writes, no modification
 * to the legacy Wine runtime or user's existing Wine prefix.
 *
 * An installed asset slot is NOT proof that native Wine + graphics can run:
 * switching the actual launcher requires signed loader/prefix handoff.
 */
public final class KernixProtonFexInstallerV49121 {
    private KernixProtonFexInstallerV49121(){}
    public static final String SLOT="proton-11.0-2-arm64ec-fex2610-pfx1";
    public static final String SCHEMA="kernix.proton-fex.bundle.v49122";
    private static final String ASSET="runtime/kernix-proton11-fex2610.zip";
    private static final String MANIFEST="runtime/kernix-proton11-fex2610-manifest.json";
    private static final String MARKER=".kernix-proton-v49122-ready";
    private static final long MAX_ZIP=420L*1024*1024;
    private static final long MAX_FILE=260L*1024*1024;
    private static final long MAX_TOTAL=2500L*1024*1024;
    private static final int MAX_ENTRIES=8000;
    public static Path slotRoot(Path appFiles){
        return appFiles.resolve("imagefs/opt").resolve(SLOT);
    }
    private static String sha(InputStream input)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");
        try(InputStream in=input){
            byte[] buf=new byte[65536];
            int n;
            while((n=in.read(buf))!=-1)if(n>0)d.update(buf,0,n);
        }
        StringBuilder s=new StringBuilder();
        for(byte b:d.digest())s.append(String.format(Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    public static boolean safeZipEntry(String name){
        if(name==null||!(name.startsWith("wine/")||name.startsWith("prefix/"))||name.length()>240
                ||name.indexOf('\\')>=0||name.indexOf('\u0000')>=0)return false;
        String rest=name.substring(name.startsWith("wine/")?5:7);
        if(rest.isEmpty()||rest.startsWith("/")||rest.startsWith("./"))return false;
        for(String seg:rest.split("/",-1))
            if(seg.isEmpty()||"..".equals(seg)||".".equals(seg))return false;
        for(int i=0;i<rest.length();i++){
            char c=rest.charAt(i);
            if(c<32||c==127||c==':'||c=='|')return false;
        }
        return true;
    }
    public static int extractRuntimeZip(Path archive,Path stage,int expected)
            throws IOException{
        if(expected<1||expected>MAX_ENTRIES
                ||Files.isSymbolicLink(archive)||!Files.isRegularFile(archive))
            throw new IOException("KERNIX_PROTON_INVALID_SOURCE_ZIP");
        if(Files.isSymbolicLink(stage)||!Files.isDirectory(stage))
            throw new IOException("KERNIX_PROTON_STAGE_NOT_PRIVATE_DIRECTORY");
        int count=0;
        long total=0L;
        byte[] buf=new byte[65536];
        java.util.HashSet<String> seen=new java.util.HashSet<>();
        try(ZipFile zip=new ZipFile(archive.toFile())){
            java.util.Enumeration<? extends ZipEntry> entries=zip.entries();
            while(entries.hasMoreElements()){
                ZipEntry e=entries.nextElement();
                if(e.isDirectory())continue;
                if(++count>MAX_ENTRIES)throw new IOException("KERNIX_PROTON_ENTRY_BUDGET");
                String name=e.getName();
                if(!safeZipEntry(name)||!seen.add(name))
                    throw new IOException("KERNIX_PROTON_UNSAFE_OR_DUPLICATE_ZIP_ENTRY");
                Path dest=(name.startsWith("wine/") ?
                    stage.resolve(name.substring(5)) :
                    stage.resolve("prefix").resolve(name.substring(7))).normalize();
                if(!dest.startsWith(stage)||Files.isSymbolicLink(dest))
                    throw new IOException("KERNIX_PROTON_ZIP_SLIP");
                Path parent=dest.getParent();
                for(Path x=parent;x!=null&&x.startsWith(stage);x=x.getParent())
                    if(Files.isSymbolicLink(x))
                        throw new IOException("KERNIX_PROTON_ZIP_PARENT_SYMLINK");
                Files.createDirectories(parent);
                long size=0L;
                try(InputStream in=zip.getInputStream(e);
                    OutputStream out=Files.newOutputStream(dest,
                        StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
                    for(int n;(n=in.read(buf))!=-1;){
                        if(n==0)continue;
                        size+=n;
                        total+=n;
                        if(size>MAX_FILE||total>MAX_TOTAL)
                            throw new IOException("KERNIX_PROTON_UNPACK_SIZE_LIMIT");
                        out.write(buf,0,n);
                    }
                }
                if(e.getSize()>=0&&e.getSize()!=size)
                    throw new IOException("KERNIX_PROTON_ENTRY_SIZE_MISMATCH");
            }
        }
        if(count!=expected)
            throw new IOException("KERNIX_PROTON_INCOMPLETE_ARCHIVE:"+count);
        for(String path:new String[]{
                "lib/wine/aarch64-windows/libarm64ecfex.dll",
                "lib/wine/aarch64-windows/libwow64fex.dll",
                "lib/wine/aarch64-unix/libarm64ecfex.so",
                "lib/wine/aarch64-unix/libwow64fex.so",
                "lib/wine/aarch64-unix/ntdll.so",
                "lib/wine/aarch64-unix/winex11.so",
                "share/wine/wine.inf",
                "lib/wine/aarch64-windows/ntdll.dll"}){
            if(!Files.isRegularFile(stage.resolve(path),LinkOption.NOFOLLOW_LINKS))
                throw new IOException("KERNIX_PROTON_REQUIRED_COMPONENT_MISSING:"+path);
        }
        // This template is separate from the active Wine prefix. Only C:
        // refers into the template; original Winlator D/E/Z links are never
        // imported or used.
        Path prefix=stage.resolve("prefix");
        for(String rel:new String[]{"system.reg","user.reg","userdef.reg"}){
            if(!Files.isRegularFile(prefix.resolve(rel),LinkOption.NOFOLLOW_LINKS))
                throw new IOException("KERNIX_PROTON_PREFIX_REGISTRY_MISSING:"+rel);
        }
        if(!Files.isDirectory(prefix.resolve("drive_c/windows/system32")))
            throw new IOException("KERNIX_PROTON_PREFIX_TREE_INCOMPLETE");
        // Upstream dosdevices/ holds only four links and AppleDouble
        // metadata. All foreign host links were deliberately excluded
        // from the signed ZIP. Recreate this EMPTY private directory
        // before publishing our own C: link.
        Path dosdevices=prefix.resolve("dosdevices");
        if(Files.exists(dosdevices,LinkOption.NOFOLLOW_LINKS)
            &&(Files.isSymbolicLink(dosdevices)||!Files.isDirectory(dosdevices)))
            throw new IOException("KERNIX_PROTON_PREFIX_DEVICE_DIR_UNSAFE");
        Files.createDirectories(dosdevices);
        Path c=prefix.resolve("dosdevices/c:");
        if(Files.exists(c,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("KERNIX_PROTON_PREFIX_C_DRIVE_UNTRUSTED");
        Files.createSymbolicLink(c,Path.of("../drive_c"));
        return count;
    }
    private static void clearInterruptedOwnedStage(Path stage)throws IOException{
        Path owner=stage.resolve(".kernix-private-install-owner");
        if(Files.isSymbolicLink(stage)
           ||Files.isSymbolicLink(owner)
           ||!Files.isRegularFile(owner,LinkOption.NOFOLLOW_LINKS)
           ||!"KERNIX_PROTON_FEX_V49121".equals(new String(Files.readAllBytes(owner),StandardCharsets.US_ASCII).trim()))
            throw new IOException("KERNIX_PROTON_UNKNOWN_STAGING_OWNER");
        // This method is scoped to one exact .installing directory beneath
        // appFiles/imagefs/opt, NOT the existing Wine prefix or game paths.
        Files.walkFileTree(stage,new java.nio.file.SimpleFileVisitor<Path>(){
            @Override public java.nio.file.FileVisitResult visitFile(Path file,
                    java.nio.file.attribute.BasicFileAttributes attrs)throws IOException{
                if(!file.normalize().startsWith(stage))
                    throw new IOException("KERNIX_PROTON_STAGE_ESCAPED");
                if(Files.isSymbolicLink(file)){
                    Path only=stage.resolve("prefix/dosdevices/c:");
                    if(!file.equals(only)
                        ||!Path.of("../drive_c").equals(Files.readSymbolicLink(file)))
                        throw new IOException("KERNIX_PROTON_UNEXPECTED_STAGE_LINK");
                }
                Files.delete(file);
                return java.nio.file.FileVisitResult.CONTINUE;
            }
            @Override public java.nio.file.FileVisitResult postVisitDirectory(
                    Path dir,IOException error)throws IOException{
                if(error!=null)throw error;
                if(!dir.normalize().startsWith(stage))
                    throw new IOException("KERNIX_PROTON_STAGE_ROOT_ESCAPED");
                Files.delete(dir);
                return java.nio.file.FileVisitResult.CONTINUE;
            }
        });
    }
    private static boolean ready(Path target,String expectedSha){
        try{
            Path marker=target.resolve(MARKER);
            if(Files.isSymbolicLink(target)||Files.isSymbolicLink(marker)
                    ||!Files.isRegularFile(marker,LinkOption.NOFOLLOW_LINKS))
                return false;
            if(!expectedSha.equals(new String(Files.readAllBytes(marker),StandardCharsets.US_ASCII).trim()))return false;
            for(String path:new String[]{
                "lib/wine/aarch64-windows/libarm64ecfex.dll",
                "lib/wine/aarch64-windows/libwow64fex.dll",
                "lib/wine/aarch64-unix/libarm64ecfex.so",
                "lib/wine/aarch64-unix/libwow64fex.so",
                "lib/wine/aarch64-unix/ntdll.so",
                "share/wine/wine.inf",
                "prefix/system.reg",
                "prefix/user.reg",
                "prefix/userdef.reg"}){
                Path file=target.resolve(path);
                if(Files.isSymbolicLink(file)
                   ||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                   ||Files.size(file)<256)return false;
            }
            Path c=target.resolve("prefix/dosdevices/c:");
            return Files.isSymbolicLink(c)
                &&Path.of("../drive_c").equals(Files.readSymbolicLink(c))
                &&Files.isDirectory(target.resolve("prefix/drive_c/windows/system32"));
        }catch(Exception ignored){return false;}
    }
    /** Only the signed native WineServer is updated between RCs; the
     * existing extracted Proton ZIP and user's writable prefix stay intact.
     * Fail closed if the current APK native server does not match the patch
     * recorded in this same APK's manifest.
     */
    private static boolean patchedServerMatched(Context ctx,JSONObject manifest)
            throws Exception {
        JSONObject patch=manifest.optJSONObject("wineserver_patch");
        if(patch==null
           ||!"SIGNED_APK_NATIVE_LIB_ONLY".equals(patch.optString("scope"))
           ||!"2c0670d0a6b5a3d4d19510f22b01d3a66de40f91".equals(
               patch.optString("source_upstream_commit"))
           ||patch.optLong("native_build_run",-1L)!=41330962355L
           ||!"libkernix_p11_server.so".equals(patch.optString("server_entry"))
           ||!patch.optBoolean("original_proton_runtime_zip_unchanged",false)
           ||!patch.optBoolean("prefix_not_reinstalled",false)
           ||patch.optBoolean("device_gui_tested",true))
            return false;
        String expected=patch.optString("elf_sha256","");
        if(!expected.matches("[0-9a-f]{64}"))return false;
        JSONArray signed=manifest.optJSONArray("signed_native");
        if(signed==null)return false;
        boolean listed=false;
        for(int i=0;i<signed.length();i++){
            JSONObject row=signed.optJSONObject(i);
            if(row!=null&&"libkernix_p11_server.so".equals(row.optString("name")))
                listed=expected.equals(row.optString("sha256"));
        }
        if(!listed)return false;
        Path server=Path.of(ctx.getApplicationInfo().nativeLibraryDir)
            .resolve("libkernix_p11_server.so");
        return !Files.isSymbolicLink(server)
            &&Files.isRegularFile(server,LinkOption.NOFOLLOW_LINKS)
            &&expected.equals(sha(Files.newInputStream(server)));
    }
    public static boolean staged(Context ctx) {
        if(ctx==null)return false;
        try(InputStream in=ctx.getAssets().open(MANIFEST)){
            JSONObject m=new JSONObject(new String(in.readAllBytes(),StandardCharsets.UTF_8));
            return SCHEMA.equals(m.getString("schema"))
                &&patchedServerMatched(ctx,m)
                &&ready(slotRoot(ctx.getFilesDir().toPath()),m.getString("zip_sha256"));
        }catch(Exception ignored){return false;}
    }
    /** Called from a non-UI thread; no global engine switch until native
     * loader, UnixLib lookup and independent prefix are verified together. */
    public static synchronized String prepare(Context ctx) {
        if(ctx==null)return "KERNIX_PROTON_CONTEXT_MISSING";
        Path pending=null,download=null;
        String result="NOT_STARTED";
        try{
            JSONObject m;
            try(InputStream in=ctx.getAssets().open(MANIFEST)){
                byte[] b=in.readNBytes(30000);
                m=new JSONObject(new String(b,StandardCharsets.UTF_8));
            }
            if(!SCHEMA.equals(m.optString("schema"))
                    ||!SLOT.equals(m.optString("slot"))
                    ||m.getInt("entry_count")<1000
                    ||m.optInt("prefix_entry_count",0)<150
                    ||m.optBoolean("prefix_external_host_links_copied",true))
                return result="INVALID_PROTON_FEX_MANIFEST";
            String digest=m.getString("zip_sha256");
            if(!digest.matches("[0-9a-f]{64}"))
                return result="PROTON_BUNDLE_SHA_MISSING";
            if(!patchedServerMatched(ctx,m))
                return result="PROTON_PATCHED_NATIVE_WINESERVER_SHA_MISMATCH";
            JSONArray signed=m.getJSONArray("signed_native");
            if(signed.length()!=39 || m.optInt("unixlib_total")!=35
                ||!m.optBoolean("all_unixlibs_signed",false)
                ||m.getJSONArray("unixlib_aliases").length()!=32)
                return result="PROTON_NATIVE_CLOSURE_INCOMPLETE";
            Path nativeRoot=Path.of(ctx.getApplicationInfo().nativeLibraryDir);
            for(int i=0;i<signed.length();i++){
                JSONObject v=signed.getJSONObject(i);
                String n=v.getString("name"),want=v.getString("sha256");
                if(!n.matches("libkernix_p11_[A-Za-z0-9_]+\\.so")
                    ||!want.matches("[0-9a-f]{64}"))
                    return result="PROTON_NATIVE_MANIFEST_INVALID";
                Path file=nativeRoot.resolve(n);
                if(Files.isSymbolicLink(file)
                    ||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
                    ||!want.equals(sha(Files.newInputStream(file))))
                    return result="PROTON_NATIVE_APK_SHA_MISMATCH:"+n;
            }
            Path target=slotRoot(ctx.getFilesDir().toPath());
            if(ready(target,digest))return result="PROTON_FEX_STAGED_NATIVE_MATCHED_ACTIVATION_PENDING";
            if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))
                return result="PROTON_EXISTING_SLOT_NOT_REPLACED";
            Path base=target.getParent();
            Files.createDirectories(base);
            download=ctx.getCacheDir().toPath().resolve("kernix-proton-v49121.pending.zip");
            if(Files.isSymbolicLink(download))return result="PROTON_UNSAFE_DOWNLOAD_PATH";
            long copied=0;
            try(InputStream in=ctx.getAssets().open(ASSET);
                OutputStream out=Files.newOutputStream(download,
                        StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING)){
                byte[] buf=new byte[65536];
                for(int n;(n=in.read(buf))!=-1;){
                    copied+=n;
                    if(copied>MAX_ZIP)throw new IOException("PROTON_ZIP_OVERSIZED");
                    out.write(buf,0,n);
                }
            }
            if(copied!=m.getLong("zip_bytes")
                    ||!digest.equals(sha(Files.newInputStream(download))))
                return result="PROTON_SOURCE_ASSET_SHA_MISMATCH";
            pending=base.resolve("."+SLOT+".installing");
            if(Files.exists(pending,LinkOption.NOFOLLOW_LINKS))
                clearInterruptedOwnedStage(pending);
            Files.createDirectory(pending);
            Files.write(pending.resolve(".kernix-private-install-owner"),
                "KERNIX_PROTON_FEX_V49121\n".getBytes(StandardCharsets.US_ASCII),
                StandardOpenOption.CREATE_NEW);
            extractRuntimeZip(download,pending,m.getInt("entry_count"));
            Files.write(pending.resolve(MARKER),
                    (digest+"\n").getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE_NEW);
            Files.move(pending,target,StandardCopyOption.ATOMIC_MOVE);
            pending=null;
            result="PROTON_FEX_STAGED_NATIVE_MATCHED_ACTIVATION_PENDING";
        }catch(Exception e){
            result="PROTON_SAFE_INSTALL_BLOCKED_"+e.getClass().getSimpleName()
                +(e.getMessage()==null?"":":"+e.getMessage());
        }finally{
            if(download!=null)try{Files.deleteIfExists(download);}catch(Exception ignored){}
            OfflineDiagnosticJournal.record(ctx,"v49121-proton-fex-integrated",
                "KERNIX_V49121_SOURCE_PACKAGE="+SLOT+"\n"
                +"KERNIX_V49121_INSTALL_STATUS="+result+"\n"
                +"KERNIX_V49121_LEGACY_WINE_PREFIX_MUTATED=false\n"
                +"KERNIX_V49121_ORIGINAL_GAME_FILES_MODIFIED=false\n"
                +"KERNIX_V49121_PROTON_GAMEPLAY_PROVEN=false");
        }
        return result;
    }
}
