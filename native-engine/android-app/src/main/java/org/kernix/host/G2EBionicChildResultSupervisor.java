package org.kernix.host;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * G2-E/B v0.27 secure-directory remediation and diagnostic-only classification, never a relaxed PASS.
 * Strict fixed pass markers (both stdout and stderr), exit 0, 8s.
 * Only whitelisted error tags / exit code / comparison booleans are surfaced:
 * no absolute private paths, stack traces, raw linker stderr or guest bytes.
 */
final class G2EBionicChildResultSupervisor {
    static final String PASS="KERNIX_G2E_ANDROID_SIGNED_GLIBC_DATA_ONLY_VERIFIED_NO_FEX";
    static final String PASS_OUT=
        "KERNIX_G2E_ANDROID_PINNED_GLIBC_SNAPSHOT_CLOSURE_DATA_ONLY_PASS_V1\n";
    static final String PASS_ERR=
        "GUEST_EXECUTED=0\nDYNAMIC_LINKER_EXECUTED=0\nFEX_EXECUTED=0\nWINE_EXECUTED=0\n";
    private static final int TIMEOUT_SECONDS=8;
    private static final int MAX_BYTES=2048;
    private G2EBionicChildResultSupervisor(){}

    private static String read(InputStream in) throws IOException {
        try (InputStream stream=in; ByteArrayOutputStream output=new ByteArrayOutputStream()) {
            byte[] buffer=new byte[256];
            int n;
            while((n=stream.read(buffer))!=-1) {
                if(output.size()+n>MAX_BYTES)throw new IOException("G2E output cap");
                output.write(buffer,0,n);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    static String classify(int exit,String out,String err) {
        if(exit==0 && PASS_OUT.equals(out) && PASS_ERR.equals(err))
            return PASS;
        String reason="UNRECOGNIZED";
        if(exit==126 && "KERNIX_G2E_BAD_FIXED_CLI\n".equals(err))
            reason="BAD_FIXED_CLI";
        else if(exit==20 && err.startsWith("KERNIX_G2E_PRIVATE_ROOT_REJECTED:")) {
            // Match only a fixed native reason tag. Never echo a path, errno,
            // arbitrary child output or private filenames to the screen.
            String tag=err.substring("KERNIX_G2E_PRIVATE_ROOT_REJECTED:".length()).trim();
            switch(tag) {
                case "APP_PATH": reason="PRIVATE_ROOT_APP_PATH";break;
                case "APP_OPEN": reason="PRIVATE_ROOT_APP_OPEN";break;
                case "APP_OWNER_OR_UNSAFE": reason="PRIVATE_ROOT_APP_OWNER_OR_UNSAFE";break;
                case "KERNIX_DIR": reason="PRIVATE_ROOT_KERNIX_DIR";break;
                case "RUNTIME_DIR": reason="PRIVATE_ROOT_RUNTIME_DIR";break;
                case "GUEST_ROOT_DIR": reason="PRIVATE_ROOT_GUEST_ROOT_DIR";break;
                case "GLIBC_ROOT_DIR": reason="PRIVATE_ROOT_GLIBC_ROOT_DIR";break;
                default: reason="PRIVATE_ROOT_UNKNOWN_STAGE";break;
            }
        }
        else if(exit==21 && err.startsWith("KERNIX_G2E_GUEST_DATA_REJECTED:")) {
            String cause=err.substring("KERNIX_G2E_GUEST_DATA_REJECTED:".length()).trim();
            switch(cause){
                case "G2E_BAD_PRIVATE_ROOT": reason="BAD_PRIVATE_ROOT";break;
                case "G2E_EXACT_GUEST_FILE_OR_DIRECTORY_REJECTED": reason="GUEST_PATH_OPEN";break;
                case "G2E_PINNED_GUEST_SHA256_SIZE_OWNER_OR_MODE_REJECTED": reason="GUEST_FILE_MODE_OWNER_SHA";break;
                case "G2C_SNAPSHOT_INVALID_INPUT": reason="SNAPSHOT_INPUT";break;
                case "G2C_SNAPSHOT_ANON_MMAP_FAILED": reason="ANON_MMAP_FAILED";break;
                case "G2C_SNAPSHOT_SHORT_READ": reason="SNAPSHOT_SHORT_READ";break;
                case "G2C_SNAPSHOT_DATA_SHA256_REJECTED": reason="SNAPSHOT_SHA";break;
                case "G2C_SNAPSHOT_READONLY_MPROTECT_FAILED": reason="MPROTECT_FAILED";break;
                case "G2E_EXACT_GLIBC_LOADER_CLOSURE_REJECTED:none": reason="CLOSURE_GRAPH";break;
                case "G2E_GUEST_PIE_IMPORT_GRAPH_MISMATCH": reason="IMPORT_GRAPH";break;
                default:
                    if(cause.startsWith("G2E_EXACT_GLIBC_LOADER_CLOSURE_REJECTED:"))
                        reason="CLOSURE_ELF_PARSER";
                    break;
            }
        } else if(exit==127 && err.contains("CANNOT LINK EXECUTABLE")) {
            reason="ANDROID_LINKER";
        }
        // Native process can crash or be blocked before it prints anything.
        // Always provide limited structured evidence, never the raw stderr.
        return "KERNIX_G2E_V026_CHILD_NOT_VERIFIED"+
            "\nEXIT_CODE="+exit+
            "\nSTDOUT_EXACT="+(PASS_OUT.equals(out) ? "1":"0")+
            "\nSTDERR_EXACT="+(PASS_ERR.equals(err) ? "1":"0")+
            "\nREASON="+reason+
            "\nGUEST_LD_LINUX_EXECUTED=0";
    }

    static String supervise(Process child) throws InterruptedException {
        ExecutorService drain=Executors.newFixedThreadPool(2,runnable->{
            Thread thread=new Thread(runnable,"kernix-g2e-stdio");
            thread.setDaemon(true);
            return thread;
        });
        Future<String> stdout=drain.submit((Callable<String>)()->read(child.getInputStream()));
        Future<String> stderr=drain.submit((Callable<String>)()->read(child.getErrorStream()));
        try {
            if(!child.waitFor(TIMEOUT_SECONDS,TimeUnit.SECONDS)) {
                child.destroyForcibly();
                child.waitFor(1,TimeUnit.SECONDS);
                return "KERNIX_G2E_V026_CHILD_TIMEOUT_8S_NO_GUEST_PASS";
            }
            final int code=child.exitValue();
            return classify(code,stdout.get(1,TimeUnit.SECONDS),
                                 stderr.get(1,TimeUnit.SECONDS));
        }catch(ExecutionException|TimeoutException error){
            child.destroyForcibly();
            return "KERNIX_G2E_V026_CHILD_PIPE_OR_OUTPUT_REJECTED";
        }finally{
            child.destroyForcibly();
            stdout.cancel(true);
            stderr.cancel(true);
            drain.shutdownNow();
        }
    }
}
