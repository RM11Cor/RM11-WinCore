package com.r4.carxpc;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** R3D8: export real on-device 07D diagnostic JSON as an ordinary Downloads file.
 *  No storage permission is required on Android 10+ for app-created downloads.
 *  This is output transport only; it cannot promote a test result to PASS.
 */
public final class R3D8JsonReportStore {
    public static final class Saved {
        public final Uri uri;
        public final String filename;
        Saved(Uri u,String name){uri=u;filename=name;}
    }
    private R3D8JsonReportStore(){}

    public static String filename(long nonce) {
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss",
            Locale.US).format(new Date());
        return "CarX_PC_R3D8_07D_Diagnostics_" + stamp + "_" +
            Long.toUnsignedString(nonce) + ".json";
    }

    public static Saved save(Context context, String json, long nonce)
            throws IOException {
        if (Build.VERSION.SDK_INT < 29)
            throw new IOException("NEEDS_ANDROID_10_OR_SYSTEM_DOCUMENT_PICKER");
        if (json == null || json.length() < 2 ||
            json.charAt(0) != '{')
            throw new IOException("DIAGNOSTIC_JSON_NOT_READY");
        final String name=filename(nonce);
        final ContentResolver resolver=context.getContentResolver();
        final ContentValues values=new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME,name);
        values.put(MediaStore.MediaColumns.MIME_TYPE,"application/json");
        values.put(MediaStore.MediaColumns.RELATIVE_PATH,
            Environment.DIRECTORY_DOWNLOADS + "/");
        values.put(MediaStore.MediaColumns.IS_PENDING,1);
        Uri uri=null;
        boolean finished=false;
        try {
            uri=resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                values);
            if (uri==null)throw new IOException("MEDIASTORE_INSERT_FAILED");
            try (OutputStream out=resolver.openOutputStream(uri,"w")) {
                if (out==null)throw new IOException("MEDIASTORE_STREAM_NULL");
                out.write(json.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
            values.clear();
            values.put(MediaStore.MediaColumns.IS_PENDING,0);
            if (resolver.update(uri,values,null,null)!=1)
                throw new IOException("MEDIASTORE_COMMIT_FAILED");
            finished=true;
            return new Saved(uri,name);
        } catch (RuntimeException e) {
            throw new IOException("MEDIASTORE_WRITE_ERROR",e);
        } finally {
            if (!finished && uri!=null) {
                try { resolver.delete(uri,null,null); }
                catch (Throwable ignored) {}
            }
        }
    }
}
