package com.r4.carxpc;

import android.content.Context;
import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * R3C21 optional, user-authorized network provision of source-verified
 * third-party Ubuntu Noble Wine guest DATA. No APK-exec, no guest exec,
 * no root/su, no shell, no executable permission grant, no credentials.
 *
 * GitHub release and archive checksum are source locked. Download streams
 * directly to the existing R3C18 private file importer: no 517MB duplicate
 * stored on external or shared storage.
 */
public final class WineGuestHttpProvisioner {
    public static final long ORIGINAL_ARCHIVE_LENGTH=517361543L;
    public static final String ORIGINAL_GUEST_ARCHIVE_URL=
        "https://github.com/RM11Cor/RM11-WinCore/releases/download/"
        +"carx-pc-wine-guest-ubuntu-noble-r3c21/"
        +"CarX_Wine_Ubuntu_Noble_x86_64_GuestRootfs_SHA256.tar.gz";

    public interface Progress {
        void onProgress(long bytesReceived,long bytesTotal);
    }
    private WineGuestHttpProvisioner(){}

    public static GuestRootfsInstaller.Receipt provision(
        Context app,Progress update)throws IOException {
        if(app==null)throw new IOException("NULL_ANDROID_CONTEXT");
        final Path privateDir=app.getFilesDir().toPath();
        if(!Files.isDirectory(privateDir,LinkOption.NOFOLLOW_LINKS)
            ||Files.isSymbolicLink(privateDir))
            throw new IOException("NOT_APP_OWNED_PRIVATE_STORAGE");
        final Path prior=privateDir.resolve(GuestRootfsInstaller.ROOTFS_NAME);
        final long minRequired=Files.isDirectory(prior,LinkOption.NOFOLLOW_LINKS)
            ?3000000000L:1750000000L;
        if(app.getFilesDir().getUsableSpace()<minRequired)
            throw new IOException("INSUFFICIENT_PRIVATE_STORAGE_MIN_BYTES_"+minRequired);
        final URL source=new URL(ORIGINAL_GUEST_ARCHIVE_URL);
        if(!"https".equalsIgnoreCase(source.getProtocol())
           ||!"github.com".equalsIgnoreCase(source.getHost()))
            throw new IOException("UNEXPECTED_ORIGIN");
        HttpURLConnection connection=(HttpURLConnection)source.openConnection();
        connection.setConnectTimeout(30000);
        connection.setReadTimeout(120000);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("Accept-Encoding","identity");
        connection.setRequestProperty("User-Agent","CarX-PC-Runtime-R3C21-SourceVerified");
        connection.setUseCaches(false);
        try {
            int code=connection.getResponseCode();
            if(code!=HttpURLConnection.HTTP_OK)
                throw new IOException("SOURCE_HTTP_NOT_200_"+code);
            // Only TLS->TLS redirects accepted; Android HttpsURLConnection
            // validates the new host against the platform trust store.
            URL finalUrl=connection.getURL();
            if(!"https".equalsIgnoreCase(finalUrl.getProtocol()))
                throw new IOException("INSECURE_HTTP_REDIRECT_BLOCKED");
            long length=connection.getContentLengthLong();
            if(length>=0 && length!=ORIGINAL_ARCHIVE_LENGTH)
                throw new IOException("SOURCE_LENGTH_DIFFERS_FROM_PINNED_INPUT_"+length);
            if(update!=null)update.onProgress(0,ORIGINAL_ARCHIVE_LENGTH);
            try(InputStream in=new BufferedInputStream(connection.getInputStream(),65536)){
                InputStream counted=new FilterInputStream(in) {
                    long received=0, next=16L*1024*1024;
                    private void count(int value)throws IOException{
                        if(value<=0)return;
                        received+=value;
                        if(received>ORIGINAL_ARCHIVE_LENGTH)
                            throw new IOException("COMPRESSED_DATA_MORE_THAN_PINNED_SIZE");
                        if(received>=next){
                            next=received+16L*1024*1024;
                            if(update!=null)update.onProgress(received,ORIGINAL_ARCHIVE_LENGTH);
                        }
                    }
                    @Override public int read()throws IOException{
                        int value=super.read();
                        if(value!=-1)count(1);
                        return value;
                    }
                    @Override public int read(byte[] bytes,int off,int length)
                            throws IOException{
                        // FilterInputStream implementation reads from raw
                        // delegate; do not call super.read(byte[]) then count
                        // twice through the one-byte read override.
                        int got=in.read(bytes,off,length);
                        count(got);
                        return got;
                    }
                };
                GuestRootfsInstaller.Receipt result=
                    GuestRootfsInstaller.install(counted,privateDir);
                if(!GuestRootfsInstaller.ARCHIVE_SHA256.equals(result.sha256))
                    throw new IOException("SOURCE_ARCHIVE_DIGEST_FAILED_AFTER_IMPORT");
                if(update!=null)update.onProgress(ORIGINAL_ARCHIVE_LENGTH,ORIGINAL_ARCHIVE_LENGTH);
                return result;
            }
        } finally {
            connection.disconnect();
        }
    }
}
