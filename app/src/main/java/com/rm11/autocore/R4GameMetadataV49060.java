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
import java.net.URLEncoder;
import org.json.JSONObject;
import org.json.JSONArray;
import android.net.Uri;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

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
                File cover=customCover(app,exe);
                if(cover==null)cover=localCover(exe);
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
                        if(appid==null)appid=steamExactTitle(title);
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
        String recognized=knownTitle(exe);
        if(recognized!=null)return recognized;
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

    /** Only known IDs and names; never guess artwork from fuzzy web search. */
    private static String identityText(File exe){
        StringBuilder b=new StringBuilder();
        File dir=exe;
        for(int i=0;i<5&&dir!=null;i++,dir=dir.getParentFile()){
            b.append(' ').append(dir.getName());
        }
        return b.toString().toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9]+"," ").trim();
    }
    private static String knownTitle(File exe){
        String t=identityText(exe);
        if(t.contains("silksong"))return "Hollow Knight: Silksong";
        if(t.contains("carx street")||t.contains("carxstreet"))return "CarX Street";
        if(t.contains("witcher 3")||t.contains("witcher3")||t.contains("wild hunt"))
            return "The Witcher 3: Wild Hunt";
        if(t.contains("cyberpunk 2077")||t.contains("cyberpunk2077"))return "Cyberpunk 2077";
        if(t.contains("grand theft auto v")||t.contains("gta v")||
           t.contains("gtav")||t.contains("playgtav"))return "Grand Theft Auto V";
        if(t.contains("red dead redemption 2")||t.contains("rdr2"))return "Red Dead Redemption 2";
        if(t.contains("forza horizon 5"))return "Forza Horizon 5";
        if(t.contains("elden ring"))return "ELDEN RING";
        if(t.contains("god of war"))return "God of War";
        if(t.contains("hollow knight"))return "Hollow Knight";
        return null;
    }
    private static String wellKnownSteamId(String title,File exe){
        String both=(title+" "+identityText(exe)).toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9]+"," ");
        if(both.contains("silksong"))return "1030300";
        if(both.contains("carx street")||both.contains("carxstreet"))return "1114150";
        if(both.contains("witcher 3")||both.contains("witcher3")||both.contains("wild hunt"))return "292030";
        if(both.contains("cyberpunk 2077")||both.contains("cyberpunk2077"))return "1091500";
        if(both.contains("grand theft auto v")||both.contains("gta v")
            ||both.contains("gtav")||both.contains("playgtav"))return "271590";
        if(both.contains("red dead redemption 2")||both.contains("rdr2"))return "1174180";
        if(both.contains("forza horizon 5"))return "1551360";
        if(both.contains("elden ring"))return "1245620";
        if(both.contains("god of war"))return "1593500";
        if(both.contains("hollow knight"))return "367520";
        return null;
    }
    /**
     * Search Steam by the detected title only when no explicit/known AppID
     * exists. Reject suggestions that don't match exactly after simple
     * punctuation/edition cleanup: a wrong game's cover is worse than none.
     * Never sends file contents, directories, or device identifiers.
     */
    private static String normalizedSteamTitle(String title){
        if(title==null)return "";
        String s=title.toLowerCase(Locale.ROOT)
            .replaceAll("(?i)\\b(game of the year|goty|complete edition|deluxe edition|definitive edition|enhanced edition|digital deluxe|standard edition)\\b","")
            .replaceAll("[^a-z0-9]+"," ").trim()
            .replaceAll("^(the|a) ","")
            .replaceAll(" +"," ");
        return s;
    }
    private static String steamExactTitle(String title){
        String normalized=normalizedSteamTitle(title);
        if(normalized.length()<4||normalized.length()>80
            ||normalized.equals("launcher")||normalized.equals("game")
            ||normalized.equals("windows game"))return null;
        HttpURLConnection con=null;
        try{
            String address="https://store.steampowered.com/api/storesearch/?term="
                +URLEncoder.encode(title,"UTF-8")+"&l=english&cc=US";
            con=(HttpURLConnection)new URL(address).openConnection();
            con.setConnectTimeout(2200);
            con.setReadTimeout(2800);
            con.setRequestProperty("User-Agent","R4PCGaming/1.0");
            if(con.getResponseCode()!=200||con.getContentLengthLong()>128_000)
                return null;
            byte[] buf=new byte[8192];
            int total=0,n;
            ByteArrayOutputStream out=new ByteArrayOutputStream(8192);
            try(InputStream in=con.getInputStream()){
                while((n=in.read(buf))!=-1){
                    total+=n;if(total>128_000)return null;
                    out.write(buf,0,n);
                }
            }
            JSONObject response=new JSONObject(out.toString("UTF-8"));
            JSONArray items=response.optJSONArray("items");
            if(items==null)return null;
            for(int i=0;i<items.length()&&i<10;i++){
                JSONObject result=items.optJSONObject(i);
                if(result==null)continue;
                if(!normalized.equals(normalizedSteamTitle(result.optString("name"))))
                    continue;
                long appid=result.optLong("id",0);
                if(appid>0&&appid<=9999999999L)return Long.toString(appid);
            }
        }catch(Exception ignored){}
        finally{if(con!=null)con.disconnect();}
        return null;
    }
    private static File customCover(Context app,File exe) {
        try{
            File f=new File(new File(app.getFilesDir(),"r4-user-covers"),
                hash(exe.getAbsolutePath())+".webp");
            return f.isFile()&&f.length()>100&&f.length()<5_000_000?f:null;
        }catch(Exception ignored){return null;}
    }
    /**
     * Optional manual fallback for titles not present in Steam or offline.
     * Stores a bounded compressed image in app-private files only;
     * never copies/changes the user's game executable or game directory.
     */
    public static boolean saveCustomCover(Context app,File exe,Uri imageUri){
        if(app==null||exe==null||imageUri==null)return false;
        try(InputStream in=app.getContentResolver().openInputStream(imageUri)){
            if(in==null)return false;
            ByteArrayOutputStream data=new ByteArrayOutputStream(128_000);
            byte[] block=new byte[8192];int total=0,n;
            while((n=in.read(block))!=-1){
                total+=n;if(total>5_000_000)return false;
                data.write(block,0,n);
            }
            byte[] raw=data.toByteArray();
            BitmapFactory.Options bounds=new BitmapFactory.Options();
            bounds.inJustDecodeBounds=true;
            BitmapFactory.decodeByteArray(raw,0,raw.length,bounds);
            if(bounds.outWidth<64||bounds.outHeight<64
                ||bounds.outWidth>8192||bounds.outHeight>8192)return false;
            BitmapFactory.Options opts=new BitmapFactory.Options();
            opts.inSampleSize=1;
            while(Math.max(bounds.outWidth,bounds.outHeight)/opts.inSampleSize>900)
                opts.inSampleSize*=2;
            opts.inPreferredConfig=Bitmap.Config.RGB_565;
            Bitmap image=BitmapFactory.decodeByteArray(raw,0,raw.length,opts);
            if(image==null)return false;
            File dir=new File(app.getFilesDir(),"r4-user-covers");
            if(!dir.isDirectory()&&!dir.mkdirs())return false;
            File target=new File(dir,hash(exe.getAbsolutePath())+".webp");
            File temp=new File(dir,target.getName()+".tmp");
            try(FileOutputStream out=new FileOutputStream(temp)){
                if(!image.compress(Bitmap.CompressFormat.WEBP,85,out))return false;
            }
            if(!temp.renameTo(target)){temp.delete();return false;}
            BITMAPS.put(exe.getAbsolutePath(),image);
            LAST_MISSING.remove(exe.getAbsolutePath());
            return true;
        }catch(Exception e){return false;}
    }
    private static String steamId(File exe){
        File dir=exe.getParentFile();
        for(int i=0;dir!=null&&i<5;i++,dir=dir.getParentFile()){
            File id=new File(dir,"steam_appid.txt");
            if(id.isFile()&&id.length()>0&&id.length()<64){
                try(FileInputStream in=new FileInputStream(id)){
                    byte[] bytes=new byte[(int)id.length()];
                    int n=in.read(bytes);
                    if(n>0){
                        String value=new String(bytes,0,n,StandardCharsets.UTF_8).trim();
                        if(value.matches("[1-9][0-9]{0,9}"))return value;
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
        // Real Steam artwork. Try two Valve CDN endpoints and two image sizes:
        // 600x900 is often missing for older titles, header usually exists.
        String[] endpoints={
            "https://cdn.cloudflare.steamstatic.com/steam/apps/"+id+"/library_600x900.jpg",
            "https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/"+id+"/library_600x900.jpg",
            "https://cdn.cloudflare.steamstatic.com/steam/apps/"+id+"/header.jpg",
            "https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/"+id+"/header.jpg"
        };
        for(String address:endpoints){
            HttpURLConnection connection=null;
            File tmp=null;
            try{
                connection=(HttpURLConnection)new URL(address).openConnection();
                connection.setConnectTimeout(2200);connection.setReadTimeout(3500);
                connection.setInstanceFollowRedirects(true);
                connection.setRequestProperty("User-Agent","R4PCGaming/1.0");
                if(connection.getResponseCode()!=200)continue;
                if(connection.getContentLengthLong()>5_000_000)continue;
                File parent=dst.getParentFile();
                if(!parent.isDirectory()&&!parent.mkdirs())return null;
                tmp=new File(parent,dst.getName()+".part");
                int total=0;
                try(InputStream input=connection.getInputStream();
                    FileOutputStream output=new FileOutputStream(tmp)){
                    byte[] block=new byte[8192];int n;
                    while((n=input.read(block))!=-1){
                        total+=n;
                        if(total>5_000_000)break;
                        output.write(block,0,n);
                    }
                }
                if(total>5_000_000)continue;
                Bitmap result=decode(tmp);
                if(result==null)continue;
                if(!tmp.renameTo(dst))tmp.delete();
                return result;
            }catch(Exception ignored){}
            finally{if(tmp!=null&&tmp.isFile()&&!tmp.equals(dst))tmp.delete();
                    if(connection!=null)connection.disconnect();}
        }
        return null;
    }
}
