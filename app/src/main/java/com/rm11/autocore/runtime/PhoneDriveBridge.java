package com.rm11.autocore.runtime;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Android 11+ opt-in, direct POSIX phone storage mapping for Wine.
 * D: maps to the current Android user's /storage/emulated/0. We never
 * modify a user-created Wine drive, and never bypass Android permissions.
 * SAF remains available for browsing when all-files access is declined.
 */
public final class PhoneDriveBridge {
    public static final String DRIVE_LETTER="D:";
    private PhoneDriveBridge() {}

    public static boolean authorized() {
        return Build.VERSION.SDK_INT>=30 && Environment.isExternalStorageManager();
    }

    public static Intent permissionIntent(Context context) {
        if(Build.VERSION.SDK_INT<30) return null;
        Intent i=new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
        i.setData(Uri.parse("package:"+context.getPackageName()));
        return i;
    }

    public static String mountIfAuthorized(Context context, RuntimeLayout layout) {
        if(!authorized()) return "RM11_V414_PHONE_DRIVE_PERMISSION_NOT_GRANTED";
        try {
            Path appRoot=layout.appFiles.toRealPath();
            Path prefix=layout.winePrefix.toRealPath();
            if(!prefix.startsWith(appRoot) || !Files.isRegularFile(layout.winePrefixMarker()))
                return "RM11_V414_PHONE_DRIVE_PREFIX_UNAVAILABLE";
            Path links=prefix.resolve("dosdevices");
            if(Files.isSymbolicLink(links) || !Files.isDirectory(links,LinkOption.NOFOLLOW_LINKS)
                    || !links.toRealPath().startsWith(prefix))
                return "RM11_V414_PHONE_DRIVE_DOSDEVICES_INVALID";
            Path external=Environment.getExternalStorageDirectory().toPath().toRealPath();
            if(!Files.isDirectory(external) || !Files.isReadable(external))
                return "RM11_V414_PHONE_DRIVE_STORAGE_NOT_READABLE";
            Path link=links.resolve("d:");
            if(Files.exists(link,LinkOption.NOFOLLOW_LINKS)) {
                if(!Files.isSymbolicLink(link))
                    return "RM11_V414_PHONE_DRIVE_D_CONFLICT_NOT_OVERWRITTEN";
                // Existing links not owned by RM11 must never be replaced.
                Path dest=Files.readSymbolicLink(link);
                if(dest.isAbsolute() && dest.normalize().equals(external))
                    return "RM11_V414_PHONE_DRIVE_MOUNTED_D_ALREADY";
                return "RM11_V414_PHONE_DRIVE_D_CONFLICT_NOT_OVERWRITTEN";
            }
            Files.createSymbolicLink(link,external);
            return "RM11_V414_PHONE_DRIVE_MOUNTED_D_SUCCESS";
        } catch(IOException | SecurityException ex) {
            return "RM11_V414_PHONE_DRIVE_MOUNT_FAILED_"+ex.getClass().getSimpleName();
        }
    }
}
