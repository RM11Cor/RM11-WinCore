package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Environment;
import android.graphics.Color;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import com.rm11.autocore.runtime.R4PrimaryExePathV49076;

/** Exactly one native EXE browser, always rooted at internal phone storage.
 * No system DocumentsUI remembered directory, no second launcher manager. */
public final class R4PrimaryExePickerV49076 {
    private R4PrimaryExePickerV49076(){}
    public static void open(Activity activity,Consumer<File> onSelected)
            throws IOException {
        Path root=R4PrimaryExePathV49076.root(
            Environment.getExternalStorageDirectory().toPath());
        new Browser(activity,root,onSelected).open();
    }
    private static final class Browser {
        private final Activity owner;
        private final Path root;
        private final Consumer<File> callback;
        private Path current;
        private AlertDialog dialog;
        private TextView location,subtitle;
        private ListView list;
        private List<R4PrimaryExePathV49076.Entry> shown=new ArrayList<>();
        Browser(Activity activity,Path base,Consumer<File> selected){
            owner=activity;root=base;current=root;callback=selected;
        }
        private int dp(int px){return Math.round(
            owner.getResources().getDisplayMetrics().density*px);}
        private Button button(String title){
            Button b=new Button(owner);
            b.setText(title);b.setAllCaps(false);b.setTextSize(13);
            b.setTextColor(Color.WHITE);return b;
        }
        void open()throws IOException{
            LinearLayout layout=new LinearLayout(owner);
            layout.setOrientation(LinearLayout.VERTICAL);
            layout.setPadding(dp(12),dp(8),dp(12),dp(4));
            location=new TextView(owner);
            location.setTextSize(13);location.setTextColor(0xffc9e7ff);
            location.setPadding(0,dp(4),0,dp(5));
            layout.addView(location,new LinearLayout.LayoutParams(-1,-2));
            LinearLayout nav=new LinearLayout(owner);
            nav.setOrientation(LinearLayout.HORIZONTAL);
            Button home=button("⌂ التخزين الداخلي");
            Button up=button("↑ رجوع");
            nav.addView(home,new LinearLayout.LayoutParams(0,dp(54),1));
            nav.addView(up,new LinearLayout.LayoutParams(0,dp(54),1));
            layout.addView(nav,new LinearLayout.LayoutParams(-1,-2));
            subtitle=new TextView(owner);
            subtitle.setTextSize(12);subtitle.setTextColor(0xffd0d0d0);
            subtitle.setPadding(0,dp(4),0,dp(7));
            layout.addView(subtitle,new LinearLayout.LayoutParams(-1,-2));
            list=new ListView(owner);
            list.setDividerHeight(1);
            layout.addView(list,new LinearLayout.LayoutParams(-1,dp(350)));
            dialog=new AlertDialog.Builder(owner)
                .setTitle("اختيار ملف لعبة EXE")
                .setView(layout)
                .setNegativeButton("إلغاء",(d,w)->{})
                .create();
            home.setOnClickListener(v->browse(root));
            up.setOnClickListener(v->{
                try{browse(R4PrimaryExePathV49076.parent(root,current));}
                catch(IOException e){error(e);}
            });
            list.setOnItemClickListener((parent,view,index,id)->{
                if(index<0||index>=shown.size())return;
                R4PrimaryExePathV49076.Entry entry=shown.get(index);
                if(entry.directory)browse(entry.path);
                else {
                    if(!R4PrimaryExePathV49076.validExe(root,entry.path)) {
                        subtitle.setText("ملف EXE غير صالح أو مو قابل للقراءة");return;
                    }
                    File exe=entry.path.toFile();
                    dialog.dismiss();
                    callback.accept(exe);
                }
            });
            browse(root); // always reset; never persist last-visited folder
            dialog.show();
            if(dialog.getWindow()!=null){
                android.util.DisplayMetrics m=owner.getResources().getDisplayMetrics();
                dialog.getWindow().setLayout(
                    Math.round(m.widthPixels*0.90f),
                    Math.min(m.heightPixels-dp(30),dp(630)));
            }
        }
        private void error(Exception e){
            if(subtitle!=null)subtitle.setText(
                "تعذر قراءة المجلد: "+e.getClass().getSimpleName());
        }
        private void browse(Path directory){
            try{
                List<R4PrimaryExePathV49076.Entry> entries=
                    R4PrimaryExePathV49076.entries(root,directory);
                current=directory;
                shown=entries;
                String relative=root.relativize(current).toString();
                location.setText(relative.isEmpty()?"التخزين الداخلي":
                    "التخزين الداخلي / "+relative);
                subtitle.setText(entries.isEmpty()
                    ?"ماكو مجلدات أو ملفات EXE بهذا المكان"
                    :"المجلدات أولاً، بعدها ملفات EXE. اختار ملف اللعبة.");
                ArrayList<String> labels=new ArrayList<>();
                for(R4PrimaryExePathV49076.Entry item:entries)
                    labels.add((item.directory?"📁  ":"🎮  ")
                        +item.path.getFileName().toString());
                list.setAdapter(new ArrayAdapter<String>(
                    owner,android.R.layout.simple_list_item_1,labels));
            }catch(IOException ex){error(ex);}
        }
    }
}
