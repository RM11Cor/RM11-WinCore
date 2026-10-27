package engine;

import com.rm11.autocore.engine.EngineDataStager;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class EngineDataStagerSelfTest {
    private static int cases;
    private static void check(boolean ok,String why) {
        if(!ok)throw new AssertionError(why);
        cases++;
    }
    private static void bundle(Path archive,String name,byte[] bytes)
            throws IOException {
        try(ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(archive))) {
            out.putNextEntry(new ZipEntry(name));
            out.write(bytes);
            out.closeEntry();
        }
    }
    private static void rejected(Path zip,Path root,String sha,String expected)
            throws Exception{
        try{
            EngineDataStager.stage(zip,root,sha);
            throw new AssertionError("UNEXPECTED_INSTALL:"+expected);
        }catch(IOException e){
            check(e.getMessage().contains(expected),
                    "wrong rejection: "+e.getMessage());
        }
    }
    public static void main(String[] argv)throws Exception {
        Path temp=Files.createTempDirectory("rm11-engine-test-");
        try{
            Path app=Files.createDirectory(temp.resolve("appfiles"));
            Path existing=app.resolve("imagefs/home/xuser/.wine/user.reg");
            Files.createDirectories(existing.getParent());
            Files.writeString(existing,"KEEP_USER_PREFIX_AND_SAVES");
            Path file=temp.resolve("signed-bundle.zip");
            bundle(file,"windows/system32/d3d11.dll",new byte[]{'M','Z',1,2,3});
            String hash=EngineDataStager.sha256(file);
            EngineDataStager.Result first=EngineDataStager.stage(file,app,hash);
            check(first.installedFiles==1&&!first.alreadyInstalled,
                    "first data side-by-side installation");
            check(Files.readString(existing).equals("KEEP_USER_PREFIX_AND_SAVES"),
                    "legacy Wine prefix must remain byte-identical");
            check(Files.exists(first.installedData.resolve(
                    "windows/system32/d3d11.dll")),"stored PE data verified");
            EngineDataStager.Result repeated=EngineDataStager.stage(file,app,hash);
            check(repeated.alreadyInstalled,"verified idempotence");
            check(first.installedData.equals(repeated.installedData),
                    "no new active prefix created on rerun");
            bundle(file,"windows/system32/dxgi.dll",new byte[]{'M','Z',8});
            rejected(file,app,hash,"ENGINE_BUNDLE_HASH_MISMATCH");
            hash=EngineDataStager.sha256(file);
            EngineDataStager.stage(file,app,hash);
            bundle(file,"../../user.reg",new byte[]{1});
            rejected(file,app,EngineDataStager.sha256(file),
                    "ENGINE_DISALLOWED_DATA_ENTRY");
            bundle(file,"windows/system32/libwineprobe.so",new byte[]{0x7f,'E','L','F'});
            rejected(file,app,EngineDataStager.sha256(file),
                    "ENGINE_DISALLOWED_DATA_ENTRY");
            bundle(file,"runtime/data/hidden-native.so",new byte[]{0x7f,'E','L','F'});
            rejected(file,app,EngineDataStager.sha256(file),
                    "ENGINE_DISALLOWED_DATA_ENTRY");
            bundle(file,"windows/system32/dxgi.dll",new byte[]{1,2,3});
            rejected(file,app,EngineDataStager.sha256(file),
                    "ENGINE_INVALID_PE_IMAGE");
            check(Files.readString(existing).equals("KEEP_USER_PREFIX_AND_SAVES"),
                    "failed installations never touch the legacy prefix");
            System.out.println("RM11_ENGINE_STAGING_HOST_TEST_PASS checks="+cases);
        } finally {
            try(java.util.stream.Stream<Path> walk=Files.walk(temp)){
                for(Path p:(Iterable<Path>)walk.sorted(
                        Comparator.reverseOrder())::iterator)
                    Files.deleteIfExists(p);
            }
        }
    }
}
