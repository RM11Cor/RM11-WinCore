package com.rm11cor.carxstreet.portlab;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.system.ErrnoException;
import android.system.Os;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.PriorityQueue;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Actual G0 bridge: reads bounded x86-64 machine-function bytes from the
 * owner's original GameAssembly.dll, through previously approved Android SAF.
 *
 * Uses the IMAGE_DIRECTORY_ENTRY_EXCEPTION / RUNTIME_FUNCTION table in the
 * original Win64 PE to find real machine-code extents. NOT guessed bytes,
 * NOT an original Unity method name/reconstruction, and NOT a gameplay port.
 *
 * Exports a SMALL offline ZIP for subsequent static x86-64 to ARM64 lifting
 * under user control; original Windows DLL and 22GB game tree stay unchanged.
 * The archive is not uploaded or distributed by this app.
 */
public final class GameAssemblyCodeBridge {
    private GameAssemblyCodeBridge() {}

    private static final int MAX_SAMPLES=256;
    private static final int MIN_SAMPLE_BYTES=4;
    private static final int MAX_SAMPLE_BYTES=320;
    private static final int MAX_EXCEPTION_BYTES=24 * 1024 * 1024;
    private static final int CHUNK_ENTRIES=8192;
    private static final long MAX_PE_FILE_BYTES=1_073_741_824L;

    private static final class Section {
        final long virtual,virtualSize,rawOffset,rawSize,flags;
        Section(long a,long b,long c,long d,long f) {
            virtual=a;virtualSize=b;rawOffset=c;rawSize=d;flags=f;
        }
    }

    private static final class Function {
        final long begin,end,unwind,rank;
        Function(long b,long e,long u) {
            begin=b;end=e;unwind=u;rank=mix64((b<<32)^e^u);
        }
    }

    public static final class ExportStats {
        public int originalPdataEntries;
        public int eligibleExecutableFunctions;
        public int chosenActualFunctionSamples;
        public int bytesExported;
        public long originalAssemblyLength;
        public long exceptionDirectorySize;
    }

    private static long mix64(long input) {
        long z=input+0x9e3779b97f4a7c15L;
        z=(z^(z>>>30))*0xbf58476d1ce4e5b9L;
        z=(z^(z>>>27))*0x94d049bb133111ebL;
        return z^(z>>>31);
    }

    private static void check(boolean truth,String why)throws IOException {
        if(!truth)throw new IOException(why);
    }

    private static int u16(byte[] a,int at)throws IOException {
        check(at>=0 && at+2<=a.length,"truncated PE uint16");
        return (a[at]&255) | ((a[at+1]&255)<<8);
    }

    private static long u32(byte[] a,int at)throws IOException {
        check(at>=0 && at+4<=a.length,"truncated PE uint32");
        return (a[at]&255L) | ((a[at+1]&255L)<<8) |
                ((a[at+2]&255L)<<16) | ((a[at+3]&255L)<<24);
    }

    private static byte[] readExact(ParcelFileDescriptor fd,long length,long offset,int size)
            throws IOException {
        check(offset>=0 && size>0 && offset<=length && size<=length-offset,
                "bounded PE source read outside original GameAssembly file");
        byte[] result=new byte[size];
        int done=0;
        while(done<size) {
            int n;
            try {
                n=Os.pread(fd.getFileDescriptor(),result,done,size-done,offset+done);
            } catch(ErrnoException failure) {
                throw new IOException("SAF source provider cannot seek read-only PE file",failure);
            }
            check(n>0,"short read from original Windows GameAssembly source file");
            done+=n;
        }
        return result;
    }

    private static long rvaToFile(List<Section> sections,long rva,long bytes,
                                  long fileSize,boolean executable) throws IOException {
        check(rva>0 && bytes>0,"empty RVA or requested length");
        for(Section s:sections) {
            long span=Math.max(s.virtualSize,s.rawSize);
            if(rva>=s.virtual && rva-s.virtual<span) {
                long delta=rva-s.virtual;
                if(executable && (s.flags & 0x20000000L)==0)
                    throw new IOException("RUNTIME_FUNCTION points to a non-executable section");
                check(delta<=s.rawSize && bytes<=s.rawSize-delta,
                        "RUNTIME_FUNCTION extends beyond file-backed executable section");
                long off=s.rawOffset+delta;
                check(off<=fileSize && bytes<=fileSize-off,
                        "RUNTIME_FUNCTION maps outside original PE file");
                return off;
            }
        }
        throw new IOException("source PE RVA not mapped to file");
    }

    public static Uri findOriginalGameAssembly(ContentResolver resolver,Uri tree)
            throws IOException {
        String rootId=DocumentsContract.getTreeDocumentId(tree);
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(tree,rootId);
        try(Cursor c=resolver.query(children,new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE
        },null,null,null)) {
            check(c!=null,"can't enumerate game root through Android SAF");
            while(c.moveToNext()) {
                String document=c.getString(0);
                String name=c.getString(1);
                String type=c.getString(2);
                if(document!=null && name!=null &&
                        name.equalsIgnoreCase("GameAssembly.dll") &&
                        !DocumentsContract.Document.MIME_TYPE_DIR.equals(type)) {
                    return DocumentsContract.buildDocumentUriUsingTree(tree,document);
                }
            }
        } catch(SecurityException denied) {
            throw new IOException("saved SAF game-folder permission expired",denied);
        }
        throw new IOException("GameAssembly.dll not found at selected CarX Street root");
    }

    public static ExportStats exportSamples(ContentResolver resolver,Uri tree,
                                            OutputStream destination)
            throws Exception {
        Uri source=findOriginalGameAssembly(resolver,tree);
        try(ParcelFileDescriptor fd=resolver.openFileDescriptor(source,"r")) {
            check(fd!=null,"can't open original GameAssembly.dll read-only");
            long fileSize=fd.getStatSize();
            check(fileSize>=4096 && fileSize<=MAX_PE_FILE_BYTES,
                    "original PE file outside 1GiB analysis limit");
            byte[] h=readExact(fd,fileSize,0,(int)Math.min(131072L,fileSize));
            check(h[0]=='M'&&h[1]=='Z',"not original Windows MZ game DLL");
            long peOffset=u32(h,0x3c);
            check(peOffset>=64 && peOffset+256<h.length,
                    "invalid PE header pointer");
            int pe=(int)peOffset;
            check(h[pe]=='P'&&h[pe+1]=='E'&&h[pe+2]==0&&h[pe+3]==0,
                    "invalid PE/COFF signature");
            check(u16(h,pe+4)==0x8664,"source GameAssembly is not x86-64 PE");
            int sectionsCount=u16(h,pe+6);
            int optionSize=u16(h,pe+20);
            check(sectionsCount>0&&sectionsCount<=128,"invalid PE section count");
            int opt=pe+24;
            check(u16(h,opt)==0x20b,"source PE must be PE32+ for Windows x64");
            check(optionSize>=112+8*4 && opt+optionSize<h.length,
                    "incomplete original PE optional/data directory");
            long exceptionRva=u32(h,opt+112+8*3);
            long exceptionSize=u32(h,opt+112+8*3+4);
            check(exceptionRva>0 && exceptionSize>=12 &&
                            exceptionSize<=MAX_EXCEPTION_BYTES &&
                            exceptionSize%12==0,
                    "Win64 exception RUNTIME_FUNCTION directory missing/malformed");
            int sect=opt+optionSize;
            check(sect+sectionsCount*40<=h.length,"truncated original PE sections");
            List<Section> sections=new ArrayList<>();
            for(int i=0;i<sectionsCount;i++) {
                int at=sect+i*40;
                long va=u32(h,at+12);
                long vSize=u32(h,at+8);
                long rawSize=u32(h,at+16);
                long rawOffset=u32(h,at+20);
                long flags=u32(h,at+36);
                check(rawSize==0 || rawOffset<=fileSize &&
                                rawSize<=fileSize-rawOffset,
                        "invalid PE raw section");
                sections.add(new Section(va,vSize,rawOffset,rawSize,flags));
            }
            long exceptionOffset=rvaToFile(
                    sections,exceptionRva,exceptionSize,fileSize,false);
            int total=(int)(exceptionSize/12);
            PriorityQueue<Function> chosen=new PriorityQueue<>(MAX_SAMPLES,
                    (a,b)->Long.compareUnsigned(b.rank,a.rank));
            int eligible=0;
            for(int base=0;base<total;base+=CHUNK_ENTRIES) {
                int batch=Math.min(CHUNK_ENTRIES,total-base);
                byte[] chunk=readExact(fd,fileSize,exceptionOffset+base*12L,batch*12);
                for(int j=0;j<batch;j++) {
                    int off=j*12;
                    long begin=u32(chunk,off);
                    long end=u32(chunk,off+4);
                    long unwind=u32(chunk,off+8);
                    long length=end-begin;
                    if(begin==0 || end<=begin ||
                            length<MIN_SAMPLE_BYTES ||
                            length>MAX_SAMPLE_BYTES)continue;
                    try {
                        rvaToFile(sections,begin,length,fileSize,true);
                    }catch(IOException ignored) {continue;}
                    eligible++;
                    Function f=new Function(begin,end,unwind);
                    if(chosen.size()<MAX_SAMPLES)chosen.offer(f);
                    else if(Long.compareUnsigned(f.rank,chosen.peek().rank)<0) {
                        chosen.poll();
                        chosen.offer(f);
                    }
                }
            }
            check(!chosen.isEmpty(),
                    "no bounded executable RUNTIME_FUNCTION bodies found in original game");
            ArrayList<Function> selected=new ArrayList<>(chosen);
            selected.sort(Comparator.comparingLong(f->f.begin));

            ExportStats stats=new ExportStats();
            stats.originalPdataEntries=total;
            stats.eligibleExecutableFunctions=eligible;
            stats.originalAssemblyLength=fileSize;
            stats.exceptionDirectorySize=exceptionSize;
            stats.chosenActualFunctionSamples=selected.size();

            JSONObject manifest=new JSONObject();
            manifest.put("schema","rm11carx.original-win64-gameassembly-bounded-function-samples.v1");
            manifest.put("game_source","original owner-selected GameAssembly.dll");
            manifest.put("source_file_size_bytes",fileSize);
            manifest.put("pe_machine","IMAGE_FILE_MACHINE_AMD64");
            manifest.put("function_boundary_source","PE RUNTIME_FUNCTION .pdata/exception table");
            manifest.put("total_exception_table_entries",total);
            manifest.put("eligible_small_executable_functions",eligible);
            manifest.put("actual_function_samples",selected.size());
            manifest.put("function_names_or_il2cpp_methods_identified",false);
            manifest.put("files_changed",false);
            manifest.put("windows_game_executable_or_full_assembly_included",false);
            manifest.put("gameplay_function_semantics_proven",false);
            manifest.put("android_arm64_carx_game_code_executed",false);
            manifest.put("no_carx_game_content_published_to_github",true);
            JSONArray entries=new JSONArray();
            try(ZipOutputStream zip=new ZipOutputStream(destination)) {
                for(Function f:selected) {
                    int n=(int)(f.end-f.begin);
                    long rawAt=rvaToFile(sections,f.begin,n,fileSize,true);
                    byte[] code=readExact(fd,fileSize,rawAt,n);
                    String filename=String.format(Locale.ROOT,
                            "code/rva_%08x.bin",f.begin);
                    ZipEntry sample=new ZipEntry(filename);
                    zip.putNextEntry(sample);
                    zip.write(code);
                    zip.closeEntry();
                    JSONObject record=new JSONObject();
                    record.put("relative_rva",f.begin);
                    record.put("length_bytes",n);
                    record.put("win64_unwind_info_rva",f.unwind);
                    record.put("zip_member",filename);
                    record.put("sha256",sha256(code));
                    record.put("original_function_gameplay_identity_confirmed",false);
                    entries.put(record);
                    stats.bytesExported+=n;
                }
                manifest.put("sample_code_bytes_total",stats.bytesExported);
                manifest.put("functions",entries);
                zip.putNextEntry(new ZipEntry("manifest.json"));
                zip.write(manifest.toString(2).getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
                zip.finish();
            }
            return stats;
        }
    }

    private static String sha256(byte[] input)throws Exception {
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(input);
        StringBuilder s=new StringBuilder(hash.length*2);
        for(byte b:hash)
            s.append(String.format(Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
}
