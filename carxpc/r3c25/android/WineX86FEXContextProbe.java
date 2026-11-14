package com.r4.carxpc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import org.json.JSONObject;

/** R3C25 real original ARM64 FEXCore x86 Linux context + guest original
 * Wine64/ld-linux ephemeral native PT_LOAD and stack coexistence proof.
 * No guest x86 instruction, no Wine / wineserver / Windows/CarX execution.
 */
public final class WineX86FEXContextProbe {
    private static boolean libraryLoaded=false;
    private WineX86FEXContextProbe(){}
    private static native String nativeProbe(byte[] originalWine,
        byte[] originalLdso,byte[] linuxInitialStack,
        long sourceWineEntry,long sourceLdsoEntry,long guestRsp);
    private static synchronized void load(){
        if(!libraryLoaded){
            System.loadLibrary("carx_wine_fex_context");
            libraryLoaded=true;
        }
    }
    public static JSONObject probe(Path appFilesDir,
            WineLinuxProcessLaunchContract.Plan plan)throws Exception{
        if(plan==null || !plan.sourceShaVerified ||
           !plan.actualX86InitialStackEncoded ||
           plan.guestPageSize!=4096 ||
           plan.observedHostNativePageSize!=4096 ||
           plan.wineProcessExecuted || plan.guestWineCodeTranslated)
            throw new IOException("R3C25_AUTHENTIC_WINE_GUEST_CONTEXT_PLAN_REJECTED");
        Path root=appFilesDir.toRealPath().resolve(GuestRootfsInstaller.ROOTFS_NAME);
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("R3C25_GUEST_ROOTFS_NOT_PRESENT");
        // Exactly the SHA-256 pinned source bytes used by R3C24, same
        // original Android app private root and canonical path bounds.
        byte[] wine=WineX86HostMappingProbe.pinned(root,
            "usr/lib/wine/wine64",WineGuestElfPreflight.WINE64_SHA256);
        byte[] ldso=WineX86HostMappingProbe.pinned(root,
            "lib64/ld-linux-x86-64.so.2",WineGuestElfPreflight.LDSO_SHA256);
        load();
        String result=nativeProbe(wine,ldso,plan.guestInitialStack,
            plan.guestWineEntry,plan.guestLoaderEntry,plan.stackRSP);
        if(result==null)throw new IOException("R3C25_FEX_CONTEXT_NATIVE_NO_REPLY");
        boolean ok=result.startsWith("PASS_REAL_FEXCORE_CONTEXT_");
        return new JSONObject()
            .put("real_original_fexcore_context_and_guest_memory_coexist",ok)
            .put("status",ok?"PASS":"FAIL")
            .put("native_fex_guest_context_result",result)
            .put("actual_fexcore_thread_created_and_guest_rip_initialized",ok)
            .put("original_wine_guest_ptload_native_mapped_during_context",ok)
            .put("original_gnu_ldso_guest_ptload_native_mapped_during_context",ok)
            .put("original_linux_64k_guest_stack_mapped_during_context",ok)
            .put("guest_initial_rip_source","GNU_X86_64_PT_INTERP_LOADER_ENTRY")
            .put("guest_x86_64_initial_rip",String.format(java.util.Locale.ROOT,
                "0x%016x",plan.guestLoaderEntry))
            .put("wine_ptload_sha256",WineGuestElfPreflight.WINE64_SHA256)
            .put("ldso_ptload_sha256",WineGuestElfPreflight.LDSO_SHA256)
            .put("native_page_size",plan.observedHostNativePageSize)
            .put("fex_x86_guest_instructions_executed",false)
            .put("fex_x86_first_interpreter_syscall_observed",false)
            .put("full_dynamic_loader_initialized",false)
            .put("wine_process_executed",false)
            .put("wineserver_started",false)
            .put("win64_pe_executed",false)
            .put("carx_game_boot_proven",false);
    }
}
