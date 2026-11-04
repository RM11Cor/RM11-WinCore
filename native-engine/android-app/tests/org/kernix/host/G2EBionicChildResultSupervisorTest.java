package org.kernix.host;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class G2EBionicChildResultSupervisorTest {
    private static final class Fake extends Process {
        final int code; final boolean hang;
        final InputStream out,err;
        boolean killed;
        Fake(int code,boolean hang,String out,String err){
            this.code=code;this.hang=hang;
            this.out=new ByteArrayInputStream(out.getBytes(StandardCharsets.UTF_8));
            this.err=new ByteArrayInputStream(err.getBytes(StandardCharsets.UTF_8));
        }
        @Override public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        @Override public InputStream getInputStream(){return out;}
        @Override public InputStream getErrorStream(){return err;}
        @Override public int waitFor(){return code;}
        @Override public boolean waitFor(long timeout,TimeUnit unit){return !hang;}
        @Override public int exitValue(){return code;}
        @Override public void destroy(){killed=true;}
        @Override public Process destroyForcibly(){killed=true;return this;}
        @Override public boolean isAlive(){return hang&&!killed;}
    }
    private static void equal(String a,String b){
        if(!a.equals(b))throw new AssertionError("Expected: "+b+" Actual: "+a);
    }
    private static void has(String value,String part){
        if(!value.contains(part))throw new AssertionError("Missing "+part+" from "+value);
    }
    public static void main(String[] args)throws Exception{
        Fake ok=new Fake(0,false,G2EBionicChildResultSupervisor.PASS_OUT,
                           G2EBionicChildResultSupervisor.PASS_ERR);
        equal(G2EBionicChildResultSupervisor.supervise(ok),
              G2EBionicChildResultSupervisor.PASS);
        if(!ok.killed)throw new AssertionError("Successful child survived");
        has(G2EBionicChildResultSupervisor.supervise(new Fake(20,false,"",
                 "KERNIX_G2E_PRIVATE_ROOT_REJECTED\n")),
                 "REASON=PRIVATE_ROOT_REJECTED");
        has(G2EBionicChildResultSupervisor.supervise(new Fake(126,false,"",
                 "KERNIX_G2E_BAD_FIXED_CLI\n")),
                 "REASON=BAD_FIXED_CLI");
        has(G2EBionicChildResultSupervisor.supervise(new Fake(21,false,"",
                 "KERNIX_G2E_GUEST_DATA_REJECTED:G2E_GUEST_PIE_IMPORT_GRAPH_MISMATCH\n")),
                 "REASON=IMPORT_GRAPH");
        has(G2EBionicChildResultSupervisor.supervise(new Fake(21,false,"",
                 "KERNIX_G2E_GUEST_DATA_REJECTED:G2E_PINNED_GUEST_SHA256_SIZE_OWNER_OR_MODE_REJECTED\n")),
                 "REASON=GUEST_FILE_MODE_OWNER_SHA");
        String linker=G2EBionicChildResultSupervisor.supervise(new Fake(127,false,"",
                 "CANNOT LINK EXECUTABLE '/data/user/0/test/secret': library missing\n"));
        has(linker,"REASON=ANDROID_LINKER");
        if(linker.contains("secret")||linker.contains("/data/"))
            throw new AssertionError("Private path leaked");
        String wrong=G2EBionicChildResultSupervisor.supervise(new Fake(0,false,
            G2EBionicChildResultSupervisor.PASS_OUT,
            G2EBionicChildResultSupervisor.PASS_ERR+"extra"));
        has(wrong,"STDOUT_EXACT=1");
        has(wrong,"STDERR_EXACT=0");
        if(wrong.contains(G2EBionicChildResultSupervisor.PASS))
            throw new AssertionError("Loose success");
        String timed=G2EBionicChildResultSupervisor.supervise(new Fake(0,true,
            G2EBionicChildResultSupervisor.PASS_OUT,
            G2EBionicChildResultSupervisor.PASS_ERR));
        equal(timed,"KERNIX_G2E_V026_CHILD_TIMEOUT_8S_NO_GUEST_PASS");
        equal(G2EBionicChildResultSupervisor.supervise(new Fake(0,false,"x".repeat(2400),"")),
              "KERNIX_G2E_V026_CHILD_PIPE_OR_OUTPUT_REJECTED");
        if(!G2EBionicDataOnlySupervisor.FLAG.equals("--kernix-g2e-pinned-glibc-data-only-v1"))
            throw new AssertionError("Native argument contract diverged");
        System.out.println("KERNIX_G2E_V026_STRICT_SUCCESS_SAFE_REASON_CLASSIFIER_NEGATIVES_PASS_NO_GUEST_EXEC");
    }
}
