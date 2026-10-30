package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Build;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.util.Base64;
import android.widget.FrameLayout;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * R4 v4.90.63 single live reference launcher.
 * The user's exact selected image is embedded in the offline HTML; dynamic
 * CSS depth, color lighting and game controls are drawn above that image.
 * native-game-index-only bridge. The selected EXE is validated by the existing
 * launcher, not passed from JavaScript as an arbitrary path.
 */
public final class R4PremiumGalleryV49062 extends FrameLayout {
    public interface Actions {
        void launch(File exe);
        void add();
        void files();
        void appearance();
        void orientation();
    }
    private final Activity owner;
    private final Actions actions;
    private final WebView web;
    private boolean pageReady,disposed;
    private int sequence;
    private final AtomicBoolean visible=new AtomicBoolean(true);
    private final Bridge bridge=new Bridge();

    public R4PremiumGalleryV49062(Activity activity,Actions actions) {
        super(activity);
        this.owner=activity;this.actions=actions;
        web=new WebView(activity);
        web.setBackgroundColor(Color.rgb(7,10,22));
        web.setLayerType(WebView.LAYER_TYPE_HARDWARE,null);
        web.setOverScrollMode(WebView.OVER_SCROLL_NEVER);
        WebSettings s=web.getSettings();
        s.setJavaScriptEnabled(true);
        // WebView can load bundled assets but not arbitrary content:// or
        // remote pages. App-specific games are only launched by index.
        s.setAllowFileAccess(true);
        s.setAllowContentAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setDomStorageEnabled(false);
        s.setJavaScriptCanOpenWindowsAutomatically(false);
        s.setSupportMultipleWindows(false);
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);
        s.setMediaPlaybackRequiresUserGesture(true);
        web.addJavascriptInterface(bridge,"Native");
        web.setWebChromeClient(new WebChromeClient());
        web.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request) {
                return true; // no navigation away from our bundled UI
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest request){
                String u=request.getUrl().toString();
                if(u.startsWith("https:")||u.startsWith("http:"))
                    return new WebResourceResponse("text/plain","UTF-8",
                        new java.io.ByteArrayInputStream(new byte[0]));
                return null;
            }
            @Override public void onPageFinished(WebView view,String url){
                if(!url.startsWith("file:///android_asset/r4/r4_exact_live.html"))return;
                pageReady=true;
                refresh();
            }
        });
        addView(web,new FrameLayout.LayoutParams(-1,-1));
        web.loadUrl("file:///android_asset/r4/r4_exact_live.html");
    }
    private void emit(String javascript){
        if(disposed||!pageReady)return;
        web.evaluateJavascript(javascript,null);
    }
    public void refresh(){
        if(disposed||!pageReady)return;
        final int refresh=++sequence;
        List<RM11GameLibraryStore.Game> games=RM11GameLibraryStore.list(owner);
        JSONArray list=new JSONArray();
        for(RM11GameLibraryStore.Game game:games){
            File exe=new File(game.path);
            try{
                JSONObject object=new JSONObject();
                object.put("id","native-"+list.length());
                object.put("name",game.title);
                object.put("genres",new JSONArray().put("Windows EXE"));
                object.put("desc","لعبة Windows مضافة إلى مكتبتك؛ اضغط تشغيل لفتحها.");
                object.put("exists",exe.isFile());
                object.put("added",game.added);
                object.put("played",game.played);
                list.put(object);
            }catch(Exception ignored){}
        }
        emit("window.r4SetGames("+list.toString()+");");
        // Decode and discover thumbnails in the background. Never allocate a
        // video frame cache; only one compressed image per item reaches JS.
        for(int i=0;i<games.size();i++){
            File exe=new File(games.get(i).path);
            if(!exe.isFile())continue;
            final int index=i;
            final String path=exe.getAbsolutePath();
            R4GameMetadataV49060.load(owner,exe,(title,bitmap,source)->{
                if(refresh!=sequence||disposed||!visible.get())return;
                List<RM11GameLibraryStore.Game> current=RM11GameLibraryStore.list(owner);
                if(index>=current.size()||!path.equals(current.get(index).path))return;
                String data="";
                if(bitmap!=null){
                    try(ByteArrayOutputStream output=new ByteArrayOutputStream(48_000)){
                        bitmap.compress(Bitmap.CompressFormat.WEBP,55,output);
                        if(output.size()<350_000)
                            data="data:image/webp;base64,"+
                                Base64.encodeToString(output.toByteArray(),Base64.NO_WRAP);
                    }catch(Exception ignored){}
                }
                emit("window.r4SetGameCover("+index+","+JSONObject.quote(data)+");");
                if(title!=null&&!title.trim().isEmpty()){
                    emit("window.r4RenameGame && window.r4RenameGame("+
                        index+","+JSONObject.quote(title)+");");
                }
            });
        }
    }
    public void pause(){
        visible.set(false);
        emit("window.r4Paused(true);");
        web.onPause();
    }
    public void resume(){
        visible.set(true);
        web.onResume();
        emit("window.r4Paused(false);");
        refresh();
    }
    public void dispose(){
        disposed=true;visible.set(false);sequence++;
        web.removeJavascriptInterface("Native");
        web.stopLoading();web.onPause();web.destroy();
    }
    private final class Bridge {
        @JavascriptInterface public void play(int idx){
            owner.runOnUiThread(()->{
                if(disposed)return;
                List<RM11GameLibraryStore.Game> games=RM11GameLibraryStore.list(owner);
                if(idx<0||idx>=games.size())return;
                File exe=new File(games.get(idx).path);
                if(RM11GameLibraryStore.allowedPath(exe))actions.launch(exe);
            });
        }
        @JavascriptInterface public void add(){
            owner.runOnUiThread(()->{if(!disposed)actions.add();});
        }
        @JavascriptInterface public void files(){
            owner.runOnUiThread(()->{if(!disposed)actions.files();});
        }
        @JavascriptInterface public void appearance(){
            owner.runOnUiThread(()->{if(!disposed)actions.appearance();});
        }
        @JavascriptInterface public void orientation(){
            owner.runOnUiThread(()->{if(!disposed)actions.orientation();});
        }
        @JavascriptInterface public void refresh(){
            owner.runOnUiThread(()->{if(!disposed)R4PremiumGalleryV49062.this.refresh();});
        }
    }
}