package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;

/**
 * Read-only component status window. This does NOT load Wine or report that
 * a bundled file is operational. Adapters will be wired in later milestones,
 * one at a time, only after concrete on-device runtime checks pass.
 */
final class RM11ComponentPanel {
    private static final int BACKGROUND=0xff121d2d;
    private static final int TEXT=0xffedf4ff;
    private static final int SUB=0xffaebed4;
    private static final int ACCENT=0xff63c5ff;

    private RM11ComponentPanel(){}

    private static boolean signedPayloadPresent(Activity host,String name){
        String dir=host.getApplicationInfo().nativeLibraryDir;
        if(dir==null)return false;
        File base=new File(dir);
        File file=new File(base,name);
        try {
            return file.isFile()&&file.getCanonicalFile().getParentFile().equals(base.getCanonicalFile())
                    &&file.length()>4096;
        }catch(Exception e){return false;}
    }

    private static String nativeStatus(Activity host,String... names){
        for(String filename:names)
            if(signedPayloadPresent(host,filename))
                return "مكتبة مضمّنة — لم يتم إثبات تشغيلها";
        return "لم يُدمج في APK بعد";
    }

    private static TextView label(Activity host,String s,int size,int color,boolean bold){
        TextView t=new TextView(host);
        t.setText(s);t.setTextSize(size);t.setTextColor(color);
        t.setTypeface(Typeface.create("sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));
        return t;
    }
    private static void item(Activity host,LinearLayout col,String title,String state){
        LinearLayout row=new LinearLayout(host);
        row.setOrientation(LinearLayout.VERTICAL);
        int dp=(int)(host.getResources().getDisplayMetrics().density*9);
        row.setPadding(dp,dp,dp,dp);
        GradientDrawable g=new GradientDrawable();g.setColor(0xff1d2b40);g.setCornerRadius(dp);
        row.setBackground(g);
        row.addView(label(host,title,16,TEXT,true));
        TextView subtitle=label(host,state,13,SUB,false);subtitle.setPadding(0,dp/3,0,0);
        row.addView(subtitle);
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.bottomMargin=dp/2;
        col.addView(row,p);
    }

    static void show(Activity host){
        int dp=(int)(host.getResources().getDisplayMetrics().density*14);
        LinearLayout body=new LinearLayout(host);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setBackgroundColor(BACKGROUND);
        body.setPadding(dp,dp,dp,dp);
        TextView title=label(host,"RM11  /  مكونات المحاكي",20,ACCENT,true);
        title.setGravity(Gravity.CENTER_VERTICAL);
        body.addView(title);
        TextView notice=label(host,
            "هذه لوحة التجهيز والربط المستقبلية. الواجهة الحالية لا تشغّل EXE، ولا تعني حالة «مضمّن» أن المحرك يعمل.",
            13,SUB,false);
        notice.setPadding(0,dp/2,0,dp);
        body.addView(notice);
        ScrollView scroll=new ScrollView(host);
        LinearLayout entries=new LinearLayout(host);
        entries.setOrientation(LinearLayout.VERTICAL);
        item(host,entries,"واجهة الملفات والأقراص","جاهزة للعرض — C: تطبيق، W: مساحة عمل، D: مجلد هاتف مصرح به");
        item(host,entries,"الماوس والكيبورد","تفاعل Android الأصلي متاح — لم يُربط إدخال Wine");
        item(host,entries,"Wine / Windows API",nativeStatus(host,"libwineprobe.so","libwine_win32u.so"));
        item(host,entries,"FEX / x86-x64 translation",nativeStatus(host,"libFEXCore.so","libfexcore.so"));
        item(host,entries,"خادم العرض X11 / Lorie",nativeStatus(host,"liblorie.so","libXlorie.so"));
        item(host,entries,"تعريف Vulkan / Turnip",nativeStatus(host,"libvulkan_freedreno.so"));
        item(host,entries,"DXVK / DirectX 9-11","غير مرتبط — يحتاج Wine + Vulkan وفحص فعلي");
        item(host,entries,"VKD3D / DirectX 12","غير مرتبط — يحتاج Wine + Vulkan وفحص فعلي");
        item(host,entries,"جلسات EXE والألعاب","غير متاحة في النسخة الحالية — بعد اختبار المحرك");
        entries.setPadding(0,0,0,dp/2);
        scroll.addView(entries);
        // The host is landscape. AlertDialog's custom-view height can be
        // UNSPECIFIED; a weight-only height=0 may hide the component list.
        // Give the list a bounded, scrollable height relative to the display.
        int displayHeight=host.getResources().getDisplayMetrics().heightPixels;
        int scrollHeight=Math.max(dp*8,Math.min(displayHeight*55/100,dp*24));
        body.addView(scroll,new LinearLayout.LayoutParams(-1,scrollHeight));
        new AlertDialog.Builder(host)
            .setView(body)
            .setPositiveButton("إغلاق",null)
            .setNeutralButton("شرح المراحل",(d,w)->new AlertDialog.Builder(host)
                .setTitle("ترتيب الربط")
                .setMessage("1. واجهة المكتب والماوس\n2. مدير الجلسة ومسارات الملفات\n"
                    +"3. Wine + طبقة الترجمة\n4. خادم العرض وخطوط Windows\n"
                    +"5. تجربة EXE بسيطة\n6. Vulkan / DXVK / VKD3D والألعاب\n\n"
                    +"ما نعلن نجاح أي مكون إلا بعد تجربة على الجهاز.")
                .setPositiveButton("موافق",null).show())
            .show();
    }
}
