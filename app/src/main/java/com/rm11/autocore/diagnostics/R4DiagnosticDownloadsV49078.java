package com.rm11.autocore.diagnostics;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.widget.Toast;
import java.io.IOException;
import java.io.OutputStream;

/** One offline archive exporter for both game and main-menu diagnostics.
 * Android 10+ MediaStore puts the file DIRECTLY in shared Download/, never
 * in Android DocumentsUI's remembered last game directory. No game files,
 * Wine prefix or caller's last-picked directory are modified. */
public final class R4DiagnosticDownloadsV49078 {
    private R4DiagnosticDownloadsV49078(){}
    private static final String ZIP_MIME="application/zip";
    public static String fileName(boolean game,long millis){
        return "RM11-"+(game?"Game":"General")+"-Diagnostics-"+millis+".zip";
    }
    public static String targetFolder(){return "Download/";}
    public static final class Result {
        public final String name;
        public final Uri uri;
        Result(String name,Uri uri){this.name=name;this.uri=uri;}
    }
    /** Caller executes off the UI thread. Atomic pending publication or
     * delete-on-error avoids leaving corrupt ZIP files in Download. */
    public static Result export(Activity context,boolean game)
            throws IOException {
        if(context==null)throw new IOException("DIAGNOSTIC_ACTIVITY_REQUIRED");
        if(Build.VERSION.SDK_INT<29)
            throw new IOException("DOWNLOADS_MEDIASTORE_REQUIRES_ANDROID_10");
        String name=fileName(game,System.currentTimeMillis());
        ContentValues values=new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME,name);
        values.put(MediaStore.MediaColumns.MIME_TYPE,ZIP_MIME);
        values.put(MediaStore.MediaColumns.RELATIVE_PATH,targetFolder());
        values.put(MediaStore.MediaColumns.IS_PENDING,1);
        ContentResolver resolver=context.getContentResolver();
        Uri uri=resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI,values);
        if(uri==null)throw new IOException("DOWNLOADS_MEDIASTORE_INSERT_FAILED");
        boolean published=false;
        try {
            try(OutputStream out=resolver.openOutputStream(uri,"w")){
                if(out==null)throw new IOException("DOWNLOADS_OUTPUT_STREAM_UNAVAILABLE");
                OfflineDiagnosticArchive.export(context,out);
                out.flush();
            } catch(Exception exportError) {
                throw new IOException("DIAGNOSTIC_ZIP_EXPORT_FAILED",exportError);
            }
            ContentValues ready=new ContentValues();
            ready.put(MediaStore.MediaColumns.IS_PENDING,0);
            if(resolver.update(uri,ready,null,null)<1)
                throw new IOException("DOWNLOADS_MEDIASTORE_PUBLISH_FAILED");
            published=true;
            return new Result(name,uri);
        }finally {
            if(!published)try{resolver.delete(uri,null,null);}
            catch(Exception ignored){}
        }
    }
    public static void save(Activity activity,boolean game){
        if(activity==null)return;
        OfflineDiagnosticJournal.record(activity,
            game?"v49078-game-downloads-request":"v49078-general-downloads-request",
            "R4_V49078_EXPORT_SCOPE="+(game?"GAME":"GENERAL")+"\n"
            +"R4_V49078_TARGET_FOLDER=Download\n"
            +"R4_V49078_USE_REMEMBERED_GAME_PICKER=false\n"
            +"R4_V49078_GAME_FILES_MODIFIED=false");
        if(Build.VERSION.SDK_INT<29){
            new AlertDialog.Builder(activity)
                .setTitle("التشخيص")
                .setMessage("الحفظ المباشر في Download يحتاج Android 10 أو أحدث.")
                .setPositiveButton("فهمت",null).show();
            return;
        }
        Toast.makeText(activity,"جاري حفظ تقرير ZIP في Download...",
            Toast.LENGTH_SHORT).show();
        Thread worker=new Thread(()->{
            try {
                Result saved=export(activity,game);
                activity.runOnUiThread(()->{
                    if(activity.isFinishing()||activity.isDestroyed())return;
                    Toast.makeText(activity,"انحفظ التقرير في Download: "+saved.name,
                        Toast.LENGTH_LONG).show();
                    // User requested direct Downloads, not the previously
                    // selected game directory in ACTION_CREATE_DOCUMENT.
                    openDownloads(activity,saved.uri);
                });
            }catch(Exception failed){
                OfflineDiagnosticJournal.record(activity,"v49078-download-export-failed",
                    "R4_V49078_FAILED="+failed.getClass().getSimpleName()+"\n"
                    +"R4_V49078_SCOPE="+(game?"GAME":"GENERAL"));
                activity.runOnUiThread(()->{
                    if(activity.isFinishing()||activity.isDestroyed())return;
                    new AlertDialog.Builder(activity)
                        .setTitle("تعذر حفظ التشخيص")
                        .setMessage("تعذر كتابة ملف ZIP داخل Download: "
                            +failed.getClass().getSimpleName()
                            +". ما تم تغيير أي ملف من ملفات الألعاب.")
                        .setPositiveButton("موافق",null).show();
                });
            }
        },"r4-v49078-export-zip-to-downloads");
        worker.setDaemon(true);
        worker.start();
    }
    public static void openDownloads(Activity activity,Uri saved){
        try {
            activity.startActivity(new Intent(DownloadManager.ACTION_VIEW_DOWNLOADS));
        }catch(Exception noDownloadsApp) {
            try{
                Intent fallback=new Intent(Intent.ACTION_VIEW);
                fallback.setDataAndType(saved,ZIP_MIME);
                fallback.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                activity.startActivity(fallback);
            }catch(Exception noViewer){
                new AlertDialog.Builder(activity)
                    .setTitle("التقرير محفوظ في Download")
                    .setMessage("افتح تطبيق الملفات في الهاتف، ثم Download. "
                        +"التقرير محفوظ داخل مجلد التنزيلات.")
                    .setPositiveButton("فهمت",null).show();
            }
        }
    }
}
