package com.rm11.autocore;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Handler;
import android.os.Looper;
import android.util.LruCache;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Set;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Zero-copy/read-only EXE identification + independently cached game artwork.
 * No game-folder mutation; no untrusted filenames used as URLs or cache paths.
 * Offline cover detection first; optional Steam CDN ONLY if steam_appid.txt
 * exists next to the selected EXE. A missing cover is a normal result.
 */
public final class R4GameMetadataV49060 {
    private R4GameMetadataV49060(){}
    private static final ExecutorService IO=Executors.newFixedThreadPool(2,r->{
        Thread t=new Thread(r,"r4-cover-resolver");t.setDaemon(true);return t;
    });
    private static final Handler MAIN=new Handler(Looper.getMainLooper());
    private static final ConcurrentHashMap<String,String> TITLES=new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String,Long> LAST_MISSING=
        new ConcurrentHashMap<>();
    private static final LruCache<String,Bitmap> BITMAPS=new LruCache<String,Bitmap>(20*1024) {
        @Override protected int sizeOf(String key,Bitmap value) {
            return Math.max(1,value.getByteCount()/1024);
        }
    };
    public interface Callback { void ready(String name,Bitmap bitmap,String source); }
    public static void load(Context context,File exe,Callback callback) {
        if(context==null||exe==null||callback==null)return;
        Context app=context.getApplicationContext();
        String key=exe.getAbsolutePath();
        Bitmap cached=BITMAPS.get(key);
        String knownTitle=TITLES.get(key);
        Long failedAt=LAST_MISSING.get(key);
        boolean recentlyMissing=failedAt!=null
            &&System.currentTimeMillis()-failedAt<5L*60*1000;
        if(cached!=null||recentlyMissing){
            String name=knownTitle!=null?knownTitle:clean(exe.getName());
            MAIN.post(()->callback.ready(name,cached,cached!=null?"MEMORY_CACHE":"MISSING_ART_CACHED"));
            return;
        }
        IO.execute(()->{
            String title=bestName(exe);
            TITLES.put(key,title);
            Bitmap art=null;
            String source="FALLBACK";
            try {
                File cover=localCover(exe);
                if(cover!=null) {
                    art=decode(cover);
                    if(art!=null)source="LOCAL_COVER";
                }
                if(art==null) {
                    File cache=new File(new File(app.getCacheDir(),"r4-cover-cache"),hash(key)+".jpg");
                    if(cache.isFile()&&cache.length()>100&&cache.length()<5_000_000){
                        art=decode(cache);
                        if(art!=null)source="STEAM_CACHE";
                    }
                    if(art==null){
                        String appid=steamId(exe);
                        if(appid==null)appid=wellKnownSteamId(title,exe);
                        if(appid!=null){
                            art=fetchSteamCover(cache,appid);
                            if(art!=null)source="STEAM_APPID_CDN";
                        }
                    }
                }
            }catch(Exception ignored){}
            final Bitmap result=art;
            final String finalSource=source;
            if(result!=null)BITMAPS.put(key,result);
            else LAST_MISSING.put(key,System.currentTimeMillis());
            MAIN.post(()->callback.ready(title,result,finalSource));
        });
    }
    private static String clean(String title) {
        if(title==null)return "";
        String s=title.replaceAll("[_]+"," ").replaceAll("(?i)\\.exe$","")
            .replaceAll("(?i)\\b(x64|win64|shipping|binaries|launcher|dx11|dx12)\\b"," ")
            .replaceAll("[ ]+"," ").trim();
        return s.length()>90?s.substring(0,90).trim():s;
    }
    private static boolean generic(String s){
        String x=s.toLowerCase(Locale.ROOT);
        return x.isEmpty()||x.matches("(?:game|launcher|shipping|unity|unityplayer|windows|win64|ue4game|ue5game|r4|app|application)(?:\\s.*)?");
    }
    public static String bestName(File exe){
        if(exe==null)return "Windows Game";
        String fallback=clean(exe.getName());
        File folder=exe.getParentFile();
        if(generic(fallback)&&folder!=null){
            String f=clean(folder.getName());
            if(!generic(f)&&f.length()>2)fallback=f;
            else if(folder.getParentFile()!=null)fallback=clean(folder.getParentFile().getName());
        }
        if(!exe.isFile()||exe.length()<128)return fallback;
        try(FileInputStream f=new FileInputStream(exe);
            FileChannel channel=f.getChannel()){
            PeVersionReader.Info v=PeVersionReader.read(channel);
            String p=clean(v.productName);
            if(!generic(p)&&p.length()>2&&!p.equalsIgnoreCase("Unity"))
                return p;
            String d=clean(v.fileDescription);
            if(!generic(d)&&d.length()>2&&!d.toLowerCase(Locale.ROOT).contains("engine"))
                return d;
        }catch(Exception ignored){}
        return fallback.isEmpty()?"Windows Game":fallback;
    }
    private static File localCover(File exe){
        File root=exe.getParentFile();
        if(root==null)return null;
        File parent=root.getParentFile();
        for(File directory:new File[]{root,parent}){
            if(directory==null||!directory.isDirectory())continue;
            String[] bases={"cover","poster","folder","library_600x900","library_capsule","artwork","boxart","game_cover","header"};
            for(String base:bases)for(String ext:new String[]{".webp",".jpg",".jpeg",".png"}){
                File candidate=new File(directory,base+ext);
                if(candidate.isFile()&&!candidate.isDirectory()
                    &&candidate.length()>100&&candidate.length()<5_000_000)
                    return candidate;
            }
        }
        return null;
    }
    private static Bitmap decode(File file) {
        try {
            BitmapFactory.Options bounds=new BitmapFactory.Options();
            bounds.inJustDecodeBounds=true;
            BitmapFactory.decodeFile(file.getPath(),bounds);
            if(bounds.outWidth<=0||bounds.outHeight<=0||bounds.outWidth>8192||bounds.outHeight>8192)
                return null;
            BitmapFactory.Options opts=new BitmapFactory.Options();
            int largest=Math.max(bounds.outWidth,bounds.outHeight);
            opts.inSampleSize=1;
            while(largest/opts.inSampleSize>800)opts.inSampleSize*=2;
            opts.inPreferredConfig=Bitmap.Config.RGB_565;
            return BitmapFactory.decodeFile(file.getPath(),opts);
        }catch(Exception ignored){return null;}
    }

    /** Curated IDs (not fuzzy web image search) to avoid showing wrong covers.
     * User's own EXE folder and PE product strings are both checked, so a
     * repacked game's missing steam_appid.txt does not prevent cover display. */
    private static String wellKnownSteamId(String title,File exe){
        String folder=exe.getParentFile()==null?"":exe.getParentFile().getName();
        String both=(title+" "+exe.getName()+" "+folder).toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9]+"," ");
        if(both.contains("carx street")||both.contains("carxstreet"))return "1114150";
        if(both.contains("silksong")||both.contains("hollow knight silk"))return "1030300";
        if(both.contains("witcher 3")||both.contains("witcher3"))return "292030";
        if(both.contains("grand theft auto v")||both.contains("gta v")||
           both.contains("gtav")||both.contains("playgtav"))return "271590";
        if(both.contains("red dead redemption 2")||both.contains("rdr2"))return "1174180";
        if(both.contains("cyberpunk 2077"))return "1091500";
        if(both.contains("forza horizon 5"))return "1551360";
        if(both.contains("elden ring"))return "1245620";
        if(both.contains("god of war"))return "1593500";
        if(both.contains("hollow knight"))return "367520";
        return null;
    }
    private static String steamId(File exe){
        File folder=exe.getParentFile();
        for(File dir:new File[]{folder,folder==null?null:folder.getParentFile()}){
            if(dir==null)continue;
            File id=new File(dir,"steam_appid.txt");
            if(id.isFile()&&id.length()>0&&id.length()<64){
                try(FileInputStream in=new FileInputStream(id)){
                    byte[] data=new byte[(int)id.length()];
                    int n=in.read(data);
                    if(n>0){
                        String number=new String(data,0,n,StandardCharsets.UTF_8).trim();
                        if(number.matches("[1-9][0-9]{0,9}"))return number;
                    }
                }catch(Exception ignored){}
            }
        }
        return null;
    }
    private static String hash(String data)throws Exception{
        byte[] bytes=MessageDigest.getInstance("SHA-256")
            .digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder();
        for(int i=0;i<12;i++)out.append(String.format(Locale.ROOT,"%02x",bytes[i]&255));
        return out.toString();
    }
    private static Bitmap fetchSteamCover(File dst,String id) {
        HttpURLConnection connection=null;
        try{
            URL url=new URL("https://cdn.cloudflare.steamstatic.com/steam/apps/"
                +id+"/library_600x900.jpg");
            connection=(HttpURLConnection)url.openConnection();
            connection.setConnectTimeout(2300);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent","R4PCGaming/1.0");
            if(connection.getResponseCode()!=200)return null;
            long size=connection.getContentLengthLong();
            if(size>5_000_000)return null;
            File parent=dst.getParentFile();
            if(!parent.exists()&&!parent.mkdirs())return null;
            File tmp=new File(parent,dst.getName()+".part");
            try(java.io.InputStream input=connection.getInputStream();
                java.io.FileOutputStream output=new java.io.FileOutputStream(tmp)){
                byte[] buf=new byte[8192];int n;int total=0;
                while((n=input.read(buf))!=-1){
                    total+=n;
                    if(total>5_000_000){tmp.delete();return null;}
                    output.write(buf,0,n);
                }
            }
            Bitmap image=decode(tmp);
            if(image==null){tmp.delete();return null;}
            if(!tmp.renameTo(dst))tmp.delete();
            return image;
        }catch(Exception ignored){return null;}
        finally {if(connection!=null)connection.disconnect();}
    }
}
