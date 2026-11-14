package com.r4.carxpc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/** Full original Ubuntu Wine rootfs fixture; synthetic corruption tests
 * are NOT device or Android Wine execution evidence. */
public final class WineGuestElfPreflightIntegrationTest {
  static void ensure(boolean b,String message){if(!b)throw new AssertionError(message);}
  static void reject(Path appDir,String label)throws Exception{
      try{
          WineGuestElfPreflight.inspect(appDir);
          throw new AssertionError("CORRUPTED_SOURCE_ACCEPTED:"+label);
      }catch(IOException expected){
          System.out.println("CARX_R3C19_EXPECTED_REJECT_"+label+" "+expected.getMessage());
      }
  }
  static void write(Path path,long offset,byte[] bytes)throws Exception {
      try(java.nio.channels.FileChannel f=java.nio.channels.FileChannel.open(path,
              StandardOpenOption.WRITE)){
          f.write(ByteBuffer.wrap(bytes),offset);
      }
  }
  public static void main(String[] args)throws Exception{
      ensure(args.length==2,"Usage: WineGuestElfPreflightIntegrationTest archive.tar.gz appFilesDir");
      Path src=Paths.get(args[0]),app=Paths.get(args[1]);
      Files.createDirectories(app);
      try(InputStream in=Files.newInputStream(src)) {
          GuestRootfsInstaller.Receipt receipt=GuestRootfsInstaller.install(in,app);
          ensure(receipt.entries>=5000,"ROOTFS_TOO_FEW_ENTRIES");
      }
      Path root=app.resolve(GuestRootfsInstaller.ROOTFS_NAME);
      WineGuestElfPreflight.Result p=WineGuestElfPreflight.inspect(app);
      ensure(p.realX86LinuxElfVerified&&p.guestInterpreterElfVerified&&
             p.kernel32Pe64Amd64Verified,"GUEST_WIN64_SOURCE_PROPERTIES_NOT_VERIFIED");
      ensure(!p.androidWineExecuted&&!p.guestLinuxX64Executed&&
             !p.win64PeAndroidExecuted&&!p.carxGameBootProven,"FALSE_EXECUTION_CLAIM");
      ensure(p.winePtLoadSegments>0&&p.interpreterPtLoadSegments>0,"GUEST_PTLOAD_MISSING");
      ensure(p.interpreter.startsWith("/"),"GUEST_INTERPRETER_NOT_ABSOLUTE");
      ensure(!p.wineDtNeeded.isEmpty(),"WINE64_EXPECTED_GUEST_DEPENDENCIES");

      System.out.println("CARX_R3C19_REAL_WINE64_ELF64_AMD64_INTERP_AND_DT_NEEDED_AUDIT_PASS"+
          " interp="+p.interpreter+
          " ptload="+p.winePtLoadSegments+
          " ldso_ptload="+p.interpreterPtLoadSegments+
          " deps="+p.wineDtNeeded+
          " missing="+p.unresolvedImmediateLibraries+
          " wine_sha256="+p.wineElfSha256+
          " interpreter_sha256="+p.interpreterElfSha256+
          " kernel32_pe_sha256="+p.kernel32PeSha256);
      int negatives=0;
      Path wine=root.resolve("usr/lib/wine/wine64");
      byte[] original=Files.readAllBytes(wine);
      // Negative 1: ARM64 guest mislabeled as AMD64.
      try{
          write(wine,18,new byte[]{(byte)183,0});
          reject(app,"EM_AARCH64_INSTEAD_OF_AMD64");negatives++;
      }finally{Files.write(wine,original);}
      // Negative 2: an actual PT_LOAD with W|X must be rejected.
      ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
      long phoff=elf.getLong(32);
      int phentsize=elf.getShort(54)&0xffff;
      int phnum=elf.getShort(56)&0xffff;
      long flagOffset=-1;
      for(int i=0;i<phnum;i++){
          int o=(int)phoff+i*phentsize;
          if(elf.getInt(o)==1){flagOffset=o+4;break;}
      }
      ensure(flagOffset>=0,"WINE64_NOT_PTLOAD");
      byte[] wx=new byte[4];ByteBuffer.wrap(wx).order(ByteOrder.LITTLE_ENDIAN).putInt(7);
      try{write(wine,flagOffset,wx);reject(app,"WX_PTLOAD");negatives++;}
      finally{Files.write(wine,original);}
      // Negative 3: Windows kernel32 cannot be replaced with an ELF library.
      Path kernel32=root.resolve("usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll");
      byte[] peBytes=Files.readAllBytes(kernel32);
      try{write(kernel32,0,new byte[]{0x7f,'E','L','F'});reject(app,"KERNEL32_MZ_SPOOF");negatives++;}
      finally{Files.write(kernel32,peBytes);}
      // Negative 4: a fake rootfs receipt cannot grant the source archive pin.
      Path stamp=root.resolve(".r4-rootfs-receipt");
      byte[] receipt=Files.readAllBytes(stamp);
      try{Files.write(stamp,"r4-fake\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
          reject(app,"ROOTFS_HASH_RECEIPT_SPOOF");negatives++;}
      finally{Files.write(stamp,receipt);}
      // Negative 5: guest ELF symlink may not escape to host system /usr.
      Path saved=root.resolve("usr/lib/wine/wine64.original-ci-backup");
      Files.move(wine,saved);
      try{
          Files.createSymbolicLink(wine,Paths.get("/etc/passwd"));
          reject(app,"HOST_SYMLINK_ESCAPE");negatives++;
          Files.delete(wine);
      }finally{
          Files.deleteIfExists(wine);
          Files.move(saved,wine);
      }
      // Prove guest source unchanged after all negative cases.
      WineGuestElfPreflight.Result restored=WineGuestElfPreflight.inspect(app);
      ensure(restored.wineElfSha256.equals(p.wineElfSha256)&&
          restored.kernel32PeSha256.equals(p.kernel32PeSha256),
          "SOURCE_BYTES_NOT_RESTORED");
      ensure(negatives==5,"EXPECTED_NEGATIVE_COUNT");
      System.out.println("CARX_R3C19_FIVE_REAL_BINARY_CORRUPTION_NEGATIVES_REJECTED");
      System.out.println("CARX_R3C19_ROOTFS_NATIVE_ELF_READER_INPUT_READY_NO_ANDROID_WINE_EXECUTION_CLAIM");
  }
}
