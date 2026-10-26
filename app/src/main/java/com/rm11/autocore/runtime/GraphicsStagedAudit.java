package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.res.AssetManager;
import org.json.JSONObject;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Locale;

/** Check signed APK assets byte-for-byte. Read-only: no DLL override or prefix write. */
public final class GraphicsStagedAudit {
    private GraphicsStagedAudit() {}

    private static String hex(byte[] bytes) {
        StringBuilder s=new StringBuilder(bytes.length*2);
        for(byte b:bytes)s.append(String.format(Locale.ROOT,"%02x",b&0xff));
        return s.toString();
    }
    private static String verify(AssetManager assets,JSONObject metadata) throws Exception {
        String path=metadata.getString("asset");
        // Allow only this fixed, signed APK asset family, never a filesystem path.
        if(!path.matches("graphics/v456/(dxvk|vkd3d)/[a-z0-9]+\\.dll"))
            throw new IllegalArgumentException("UNTRUSTED_GRAPHICS_ASSET");
        long expectedLength=metadata.getLong("bytes");
        if(expectedLength<32768 || expectedLength>40L*1024*1024)
            throw new IllegalArgumentException("INVALID_COMPONENT_LENGTH");
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        long total=0;
        try(InputStream in=assets.open(path)) {
            byte[] chunk=new byte[32768];
            for(int n;(n=in.read(chunk))!=-1;) {
                total+=n;
                if(total>expectedLength)throw new IllegalArgumentException("COMPONENT_OVERSIZE");
                sha.update(chunk,0,n);
            }
        }
        if(total!=expectedLength
                || !hex(sha.digest()).equalsIgnoreCase(metadata.getString("sha256")))
            throw new IllegalArgumentException("SIGNED_APK_COMPONENT_HASH_MISMATCH");
        return "بصمة SHA-256 مطابقة";
    }

    public static String inspect(Context context) {
        AssetManager assets=context.getAssets();
        StringBuilder out=new StringBuilder("\n\nحزم الرسومات الرسمية (داخل APK)\n");
        try {
            byte[] bytes;
            try(InputStream in=assets.open("graphics/v456/manifest.json")) {
                java.io.ByteArrayOutputStream data=new java.io.ByteArrayOutputStream();
                byte[] buffer=new byte[2048];
                int n;
                while((n=in.read(buffer))!=-1) {
                    if(data.size()+n>65536)throw new IllegalArgumentException("MANIFEST_TOO_LARGE");
                    data.write(buffer,0,n);
                }
                bytes=data.toByteArray();
            }
            JSONObject manifest=new JSONObject(new String(bytes,java.nio.charset.StandardCharsets.UTF_8));
            if(!"rm11.graphics.staged.v456".equals(manifest.getString("schema"))
                    || manifest.getBoolean("active"))
                throw new IllegalArgumentException("Unexpected graphics manifest");
            JSONObject components=manifest.getJSONObject("components");
            for(String key:new String[]{"dxvk","vkd3d"}) {
                JSONObject packageInfo=components.getJSONObject(key);
                JSONObject dlls=packageInfo.getJSONObject("dlls");
                out.append(key.equals("dxvk")?"DXVK ":"VKD3D-Proton ")
                   .append(packageInfo.getString("version")).append(":\n");
                for(java.util.Iterator<String> it=dlls.keys();it.hasNext();) {
                    String name=it.next();
                    out.append("  ").append(name).append(": ");
                    try {out.append(verify(assets,dlls.getJSONObject(name)));}
                    catch(Exception e){out.append("فشل التحقق: ").append(e.getMessage());}
                    out.append('\n');
                }
            }
            out.append("الحالة: مخزّنة ومتحقّق منها فقط، غير مفعّلة داخل Wine.\n");
        }catch(Exception e) {
            out.append("حزم v4.0.56 غير موجودة أو غير سليمة: ")
                .append(e.getClass().getSimpleName()).append(": ")
                .append(e.getMessage()).append('\n');
        }
        out.append("تعريف Turnip: غير مدمج بعد، ويلزم التحقق من ABI وVulkan ICD.\n");
        return out.toString();
    }
}
