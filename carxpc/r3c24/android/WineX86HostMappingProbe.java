package com.r4.carxpc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONObject;

/**
 * R3C24 native, transient actual guest x86-64 Wine64 and GNU interpreter
 * PT_LOAD/stack memory proof. JNI receives SHA-256 verified SOURCE BYTES,
 * not executable Linux files passed to Android Bionic execve.
 * No Wine guest FEX thread, Windows PE, wineserver or game execution.
 */
public final class WineX86HostMappingProbe {
    private static boolean nativeLoaded=false;
    private WineX86HostMappingProbe(){}
    private static native String nativeProbe(
        byte[] wine,byte[] interpreter,byte[] guestStack,
        long wineEntry,long interpreterEntry,long guestRsp);
    private static synchronized void loadNative(){
        if(!nativeLoaded){
            System.loadLibrary("carx_wine_x86_ptload");
            nativeLoaded=true;
        }
    }
    private static String digest(byte[] data)throws Exception{
        byte[] out=MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder b=new StringBuilder(64);
        for(byte value:out)
            b.append(String.format(Locale.ROOT,"%02x",value&255));
        return b.toString();
    }
    private static byte[] pinned(Path root,String path,String expected)throws Exception{
        Path source=root.resolve(path).normalize();
        if(!source.startsWith(root) ||
           !Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS) ||
           Files.isSymbolicLink(source))
            throw new IOException("R3C24_SOURCE_NOT_REGULAR_APP_OWNED_FILE");
        Path real=source.toRealPath();
        if(!real.startsWith(root))
            throw new IOException("R3C24_APP_PRIVATE_ROOT_ESCAPE");
        if(Files.size(real)>2*1024*1024L)
            throw new IOException("R3C24_GUEST_FILE_TOO_LARGE");
        byte[] bytes=Files.readAllBytes(real);
        if(!digest(bytes).equals(expected))
            throw new IOException("R3C24_SOURCE_BYTE_ARRAY_SHA256_MISMATCH");
        return bytes;
    }
    public static JSONObject probe(Path appFilesDir,
            WineLinuxProcessLaunchContract.Plan p)throws Exception {
        if(p==null||!p.sourceShaVerified||!p.actualX86InitialStackEncoded)
            throw new IOException("R3C24_GUEST_SOURCE_ABI_PLAN_MISSING");
        if(p.guestPageSize!=4096||p.observedHostNativePageSize!=4096)
            throw new IOException("R3C24_DEVICE_16K_SUBPAGE_MEDIATION_NOT_READY");
        if(p.wineProcessExecuted||p.guestHostMemoryReserved ||
           p.guestWineCodeTranslated||p.wineserverSpawned)
            throw new IOException("R3C24_UNTRUSTED_GUEST_EXECUTION_CLAIM");
        Path root=appFilesDir.toRealPath().resolve(GuestRootfsInstaller.ROOTFS_NAME);
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||
            Files.isSymbolicLink(root))
            throw new IOException("R3C24_ORIGINAL_WINE_GUEST_DIR_INVALID");
        // Rehash the actual byte[] passed to native. Immutable object inputs,
        // not a second read from guest filesystem after Java verification.
        byte[] wine=pinned(root,"usr/lib/wine/wine64",
                          WineGuestElfPreflight.WINE64_SHA256);
        // PT_INTERP is part of the independently source-authenticated plan.
        // Never use host interpreter or Bionic /system/bin/linker64.
        byte[] ldso=pinned(root,"lib64/ld-linux-x86-64.so.2",
                    WineGuestElfPreflight.LDSO_SHA256);
        loadNative();
        String response=nativeProbe(wine,ldso,p.guestInitialStack,
            p.guestWineEntry,p.guestLoaderEntry,p.stackRSP);
        if(response==null)throw new IOException("R3C24_NATIVE_NO_RESULT");
        JSONObject out=new JSONObject();
        boolean ok=response.startsWith("PASS_");
        out.put("native_ptload_memory_mapping_verified",ok)
           .put("status",ok?"PASS":"FAIL")
           .put("native_mapping_result",response)
           .put("source_wine_byte_array_sha256",WineGuestElfPreflight.WINE64_SHA256)
           .put("source_ldso_byte_array_sha256",WineGuestElfPreflight.LDSO_SHA256)
           .put("host_native_page_size",p.observedHostNativePageSize)
           .put("guest_initial_stack_was_mapped",ok)
           .put("original_wine64_ptload_segments",p.wine.loadSegments.size())
           .put("original_ldso_ptload_segments",p.ldso.loadSegments.size())
           .put("original_wine_entry_virtual",String.format(
              Locale.ROOT,"0x%016x",p.guestWineEntry))
           .put("original_ldso_entry_virtual",String.format(
              Locale.ROOT,"0x%016x",p.guestLoaderEntry))
           .put("mapped_guest_regions_unmapped_on_return",true)
           .put("native_anonymous_rx_pages_source_byte_verified",ok)
           .put("wine_x64_instructions_executed_by_fex",false)
           .put("guest_glibc_initialization_complete",false)
           .put("guest_linux_wine_process_started",false)
           .put("wineserver_spawned",false)
           .put("windows_pe_executed",false)
           .put("carx_game_executed",false);
        return out;
    }
}
