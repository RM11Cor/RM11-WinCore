package com.rm11.autocore;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Device-local game library: paths only. Never copy/delete EXE or game assets.
 * The source directory remains untouched. An update preserves preferences.
 */
public final class RM11GameLibraryStore {
    public static final int MAX_GAMES=64;
    private static final String PREF="rm11_v49038_game_library",KEY="items";
    public static final class Game {
        public final String path,title;
        public final long added,played;
        public Game(String p,String t,long a,long l){path=p;title=t;added=a;played=l;}
        public String fileName(){return new File(path).getName();}
    }
    private RM11GameLibraryStore(){}
    public static boolean validExe(String filename){
        return filename!=null && filename.length()>4
            && filename.toLowerCase(Locale.ROOT).endsWith(".exe");
    }
    public static boolean allowedPath(File file){
        return file!=null && validExe(file.getName())
            && file.isFile() && file.length()>64;
    }
    public static synchronized List<Game> list(Context app) {
        ArrayList<Game> games=new ArrayList<>();
        String saved=app.getSharedPreferences(PREF,Context.MODE_PRIVATE)
                .getString(KEY,"[]");
        try{
            JSONArray array=new JSONArray(saved);
            for(int i=0;i<array.length()&&games.size()<MAX_GAMES;i++){
                JSONObject entry=array.optJSONObject(i);
                if(entry==null)continue;
                String path=entry.optString("path","");
                if(path.isEmpty()||!validExe(new File(path).getName()))continue;
                boolean dup=false;
                for(Game item:games)if(item.path.equals(path)){dup=true;break;}
                if(!dup)games.add(new Game(path,
                    entry.optString("title",new File(path).getName()),
                    entry.optLong("added",0),entry.optLong("played",0)));
            }
        }catch(Exception ignored){}
        return games;
    }
    private static synchronized void save(Context app,List<Game> games){
        JSONArray array=new JSONArray();
        for(Game entry:games){
            if(array.length()>=MAX_GAMES)break;
            try{
                JSONObject value=new JSONObject();
                value.put("path",entry.path);
                value.put("title",entry.title);
                value.put("added",entry.added);
                value.put("played",entry.played);
                array.put(value);
            }catch(Exception ignored){}
        }
        app.getSharedPreferences(PREF,Context.MODE_PRIVATE).edit()
                .putString(KEY,array.toString()).apply();
    }
    public static synchronized boolean add(Context app,File exe){
        if(!allowedPath(exe))return false;
        String path;
        try{path=exe.getCanonicalPath();}catch(Exception e){return false;}
        List<Game> games=list(app);
        for(Game item:games)if(item.path.equals(path))return true;
        if(games.size()>=MAX_GAMES)return false;
        String title=exe.getName().replaceFirst("(?i)\\.exe$","");
        games.add(0,new Game(path,title,System.currentTimeMillis(),0));
        save(app,games);
        return true;
    }
    public static synchronized void remove(Context app,String path){
        List<Game> games=list(app);
        games.removeIf(g->g.path.equals(path));
        save(app,games);
    }
    public static synchronized void played(Context app,String path) {
        List<Game> games=list(app);
        for(int i=0;i<games.size();i++) {
            Game g=games.get(i);
            if(!g.path.equals(path))continue;
            games.remove(i);
            games.add(0,new Game(g.path,g.title,g.added,System.currentTimeMillis()));
            break;
        }
        save(app,games);
    }
}
