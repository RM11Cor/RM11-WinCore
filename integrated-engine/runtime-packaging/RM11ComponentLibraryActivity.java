package com.winlator.star.rm11;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.content.Intent;
import android.net.Uri;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Read-only upstream version browser. Does not install or activate remote builds. */
public final class RM11ComponentLibraryActivity extends Activity {
    private LinearLayout list;
    private TextView status;
    private static final int MAX_CATALOG_BYTES = 1024 * 1024;
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setPadding(24,24,24,24);
        root.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(root);
        TextView title = label("RM11-WinCore | مكتبة المكونات", 23);
        title.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        root.addView(title);
        root.addView(label("الإصدارات أدناه مكتشفة من المصادر الرسمية، وليست بالضرورة مهيأة لـAndroid أو مثبتة. اختيار النسخة المستخدمة لكل لعبة يتم من إعدادات المحرك المتوافقة، وليس من هذه القائمة.",15));
        status = label("",14);
        root.addView(status);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        root.addView(list);
        setContentView(scroll);
        populate();
    }

    private TextView label(String value,int sp) {
        TextView text=new TextView(this);
        text.setText(value);
        text.setTextSize(sp);
        text.setTextIsSelectable(true);
        text.setPadding(0,12,0,12);
        return text;
    }

    private String readCatalog() throws Exception {
        try(InputStream input=getAssets().open("rm11_component_versions.json");
            ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[8192];
            int n;
            while((n=input.read(buffer))!=-1) {
                if(out.size()+n>MAX_CATALOG_BYTES)
                    throw new IllegalArgumentException("Catalog too large");
                out.write(buffer,0,n);
            }
            return out.toString("UTF-8");
        }
    }

    private void populate(){
        try {
            JSONObject catalog=new JSONObject(readCatalog());
            if(catalog.optInt("schema")!=1) throw new IllegalArgumentException("Catalog schema");
            JSONArray components=catalog.getJSONArray("components");
            status.setText("مصدر القائمة: كتالوج محفوظ بتاريخ بناء APK. تحديث GitHub اليومي لا يغيّر محتوى APK المثبّت تلقائياً. عدد الأنواع: "+components.length());
            for(int i=0;i<components.length();i++){
                final JSONObject item=components.getJSONObject(i);
                String name=item.optString("name",item.optString("id"));
                JSONArray versions=item.optJSONArray("versions");
                int count=versions==null?0:versions.length();
                String latest=item.optString("upstream_latest_seen","—");
                Button button=new Button(this);
                button.setAllCaps(false);
                button.setText(name+" | "+count+" إصدار مكتشف | أحدث مصدر: "+latest);
                list.addView(button);
                button.setOnClickListener(v->showVersions(item));
            }
        }catch(Exception ex){
            status.setText("تعذر فتح كتالوج الإصدارات داخل APK: "+ex.getClass().getSimpleName());
        }
    }

    private void showVersions(JSONObject item){
        String name=item.optString("name",item.optString("id"));
        JSONArray arr=item.optJSONArray("versions");
        if(arr==null || arr.length()==0){
            new AlertDialog.Builder(this).setTitle(name).setMessage(
                "لم تُسجَّل نسخ تم التحقق منها بعد. بعض تعريفات Turnip تحتاج حزم Android/Adreno واختبار WSI محدداً."
            ).setPositiveButton("حسناً",null).show();
            return;
        }
        final String[] versions=new String[arr.length()];
        for(int i=0;i<arr.length();i++){
            JSONObject v=arr.optJSONObject(i);
            versions[i]=v==null?"غير معروف":v.optString("tag");
        }
        new AlertDialog.Builder(this)
            .setTitle(name+" | إصدارات المصدر (ليست مثبتة)")
            .setItems(versions,(dialog,which)->{
                JSONObject v=arr.optJSONObject(which);
                if(v==null)return;
                String uri=v.optString("source_url","");
                String message="الإصدار: "+v.optString("tag")+
                    "\nحالة Android ABI: "+(v.optBoolean("abi_verified")?"متحقق":"غير متحقق")+
                    "\nقابل للتثبيت: "+(v.optBoolean("installable")?"نعم":"لا")+
                    "\nاختبار المحرك: "+(v.optBoolean("runtime_tested")?"مكتمل":"غير مكتمل")+
                    "\nلا يتم تنزيل أو تشغيل أي ملف من هذا الزر.";
                AlertDialog.Builder b=new AlertDialog.Builder(this)
                    .setTitle(name).setMessage(message).setNegativeButton("إغلاق",null);
                if(uri.startsWith("https://github.com/"))
                    b.setPositiveButton("فتح المصدر",(d,w)->startActivity(
                        new Intent(Intent.ACTION_VIEW,Uri.parse(uri))));
                b.show();
            }).setNegativeButton("رجوع",null).show();
    }
}
