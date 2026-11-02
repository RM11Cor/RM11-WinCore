package com.winlator.star.kernix;

import android.content.ContentResolver;
import android.net.Uri;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Read-only bounded offline analysis of user-selected Wine text or wine_debug.zip. */
public final class KernixWineLogAnalyzer {
    private static final int MAX_ARCHIVE_BYTES=16*1024*1024;
    private static final int MAX_LOG_BYTES=8*1024*1024;
    private KernixWineLogAnalyzer() {}

    private static byte[] bounded(InputStream in,int max) throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        byte[] chunk=new byte[8192]; int n;
        while ((n=in.read(chunk))!=-1) {
            if (out.size()+n>max) throw new IllegalArgumentException("Report exceeds 8/16 MB safety limit");
            out.write(chunk,0,n);
        }
        return out.toByteArray();
    }

    public static String analyze(ContentResolver resolver, Uri uri) throws Exception {
        byte[] raw;
        try(InputStream in=resolver.openInputStream(uri)) {
            if(in==null) throw new IllegalArgumentException("Cannot read selected report");
            raw=bounded(in,MAX_ARCHIVE_BYTES);
        }
        byte[] log=raw;
        if(raw.length>=4 && raw[0]=='P' && raw[1]=='K') {
            int matched=0;
            try(ZipInputStream zip=new ZipInputStream(new java.io.ByteArrayInputStream(raw))) {
                ZipEntry entry;
                while((entry=zip.getNextEntry())!=null) {
                    if (!entry.isDirectory() && "wine_debug.log".equals(entry.getName())) {
                        matched++;
                        if(matched>1) throw new IllegalArgumentException("Duplicate Wine log");
                        log=bounded(zip,MAX_LOG_BYTES);
                    }
                    zip.closeEntry();
                }
            }
            if(matched!=1) throw new IllegalArgumentException("ZIP must contain wine_debug.log");
        } else if(raw.length>MAX_LOG_BYTES) {
            throw new IllegalArgumentException("Wine text log too large");
        }
        String[] lines=new String(log,StandardCharsets.UTF_8).split("\n");
        int fex=0,halt=0,breakpoint=0,debugger=0,d3d12=0,vulkan=0;
        int haltLine=-1,breakpointLine=-1;
        String offset="لم يتوفر";
        for(int i=0;i<lines.length;i++){
            String l=lines[i];if(l.length()>32768)continue;
            String lower=l.toLowerCase(java.util.Locale.ROOT);
            if(lower.contains("loaded") && lower.contains("libarm64ecfex.dll"))fex++;
            if(lower.contains("loaded") && lower.contains("d3d12.dll"))d3d12++;
            if(lower.contains("loaded") && lower.contains("vulkan-1.dll"))vulkan++;
            if(lower.contains("find any available virtual memory start addresses") &&
               lower.contains("after 16 tries")) {halt++;if(haltLine<0)haltLine=i+1;}
            if(lower.contains("exception 0x80000003")) {breakpoint++;if(breakpointLine<0)breakpointLine=i+1;}
            if(lower.contains("winedbg: internal crash"))debugger++;
            int module=lower.indexOf("tlou-ii+0x");
            if(module>=0){
                int end=module+10;
                while(end<lower.length() && Character.digit(lower.charAt(end),16)>=0)end++;
                offset=lower.substring(module,end);
            }
        }
        return "KERNIX — تحليل سجل Wine (بدون تشغيل اللعبة)\n\n" +
            "تحميل FEX ARM64EC: "+fex+" إشارة\n"+
            "تحميل d3d12.dll: "+d3d12+" إشارة\n"+
            "تحميل vulkan-1.dll: "+vulkan+" إشارة\n"+
            "فشل العثور على عنوان ذاكرة: "+halt+" إشارة، أول سطر "+haltLine+"\n"+
            "استثناء 0x80000003: "+breakpoint+" إشارة، أول سطر "+breakpointLine+"\n"+
            "فشل winedbg: "+debugger+" إشارة\n"+
            "موضع اللعبة المبلغ: "+offset+"\n"+
            "فشل الذاكرة ظهر قبل الاستثناء: "+
               (haltLine>0&&breakpointLine>haltLine?"نعم": "غير مثبت")+"\n\n"+
            "ملاحظة: هذه رسائل السجل فقط. لا تثبت السبب الجذري، ولا أن مكتبات D3D12 أنشأت جهاز الرسم أو أول إطار.\n"+
            "نوع الملف والمكونات المحملة فعلياً أثناء التشغيل يحتاجان قياساً مستقلاً.";
    }
}
