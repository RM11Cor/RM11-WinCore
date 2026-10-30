package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Live six-profile gallery. No gameplay or Wine options live here. */
public final class RM11AppearanceActivity extends Activity {
    private GridLayout previews;
    private LinearLayout options;
    private TextView selectedName;
    private int dp(float x){return Math.round(getResources().getDisplayMetrics().density*x);}
    private int selected(){return RM11UiThemesV49059.selected(this);}
    private TextView label(String text,int size,boolean strong){
        TextView v=new TextView(this);v.setText(text);v.setTextSize(size);
        v.setTextColor(Color.WHITE);
        if(strong)v.setTypeface(android.graphics.Typeface.DEFAULT,
            android.graphics.Typeface.BOLD);
        v.setGravity(Gravity.CENTER_VERTICAL);
        return v;
    }
    private Button button(String text,int color,View.OnClickListener action){
        Button b=new Button(this);b.setText(text);b.setAllCaps(false);
        b.setTextSize(13);b.setTextColor(Color.WHITE);b.setMinHeight(0);
        b.setMinimumHeight(0);b.setOnClickListener(action);
        GradientDrawable bg=new GradientDrawable();
        bg.setColor(color);bg.setCornerRadius(dp(13));
        b.setBackground(bg);return b;
    }
    private LinearLayout vertical(){
        LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);
        return v;
    }
    private LinearLayout.LayoutParams match(int height){
        return new LinearLayout.LayoutParams(-1,height<0?height:dp(height));
    }
    @Override protected void onCreate(Bundle b){
        super.onCreate(b);
        RM11UiThemesV49059.applyOrientation(this);
        int profile=selected();
        getWindow().setStatusBarColor(RM11UiThemesV49059.background(profile));
        getWindow().setNavigationBarColor(RM11UiThemesV49059.background(profile));
        FrameLayout shell=new FrameLayout(this);
        shell.addView(new RM11UiThemesV49059.AnimatedScene(this,profile),
            new FrameLayout.LayoutParams(-1,-1));
        ScrollView scroller=new ScrollView(this);scroller.setFillViewport(true);
        LinearLayout root=vertical();root.setPadding(dp(18),dp(15),dp(18),dp(24));
        TextView header=label("✦ معرض أنماط RM11-WinCore",23,true);
        root.addView(header,match(47));
        TextView sub=label("ست واجهات مختلفة • غيّر الشكل بأي وقت بدون المساس بالألعاب",13,false);
        sub.setTextColor(0xffc7d5e5);root.addView(sub,match(52));
        selectedName=label("",18,true);root.addView(selectedName,match(48));
        TextView help=label("اضغط أي معاينة حتى تعتمد النمط فوراً",13,false);
        help.setTextColor(0xffa8bed4);root.addView(help,match(36));
        previews=new GridLayout(this);
        previews.setColumnCount(isPortrait()?2:3);
        previews.setUseDefaultMargins(false);
        root.addView(previews,match(-2));
        TextView caption=label("اتجاه الواجهة الرئيسية ومستكشف الملفات",18,true);
        root.addView(caption,match(56));
        options=vertical();root.addView(options,match(-2));
        TextView note=label("تأثيرات العمق والحركة للواجهة فقط، وتنتهي عند تشغيل اللعبة. شاشة اللعبة نفسها تبقى بوضعها المناسب.",13,false);
        note.setTextColor(0xffb0c9d9);note.setPadding(0,dp(14),0,dp(16));
        root.addView(note,match(-2));
        root.addView(button("✓ الرجوع لمكتبة الألعاب",RM11UiThemesV49059.accent(profile),
            v->finish()),match(51));
        scroller.addView(root);
        shell.addView(scroller,new FrameLayout.LayoutParams(-1,-1));
        setContentView(shell);
        render();
    }
    private boolean isPortrait(){
        return getResources().getConfiguration().orientation
            !=android.content.res.Configuration.ORIENTATION_LANDSCAPE;
    }
    private void render(){
        int current=selected();selectedName.setText(
            "النمط المحدد: "+RM11UiThemesV49059.NAMES[current]);
        previews.removeAllViews();
        int cols=isPortrait()?2:3;
        int widthDp=Math.max(310,getResources().getConfiguration().screenWidthDp);
        int cell=Math.max(125,(widthDp-50)/cols-12);
        for(int i=0;i<RM11UiThemesV49059.COUNT;i++){
            final int index=i;
            boolean chosen=i==current;
            LinearLayout card=vertical();
            card.setPadding(dp(8),dp(8),dp(8),dp(9));
            GradientDrawable box=RM11UiThemesV49059.panel(i,16,
                getResources().getDisplayMetrics().density);
            if(chosen)box.setStroke(dp(2),RM11UiThemesV49059.accent(i));
            card.setBackground(box);
            FrameLayout art=new FrameLayout(this);
            art.addView(new MiniPreview(i),new FrameLayout.LayoutParams(-1,-1));
            TextView tag=label("0"+(i+1),13,true);
            tag.setTextColor(RM11UiThemesV49059.accent(i));
            FrameLayout.LayoutParams tagPos=new FrameLayout.LayoutParams(
                dp(33),dp(27),Gravity.TOP|Gravity.RIGHT);
            tagPos.setMargins(0,dp(5),dp(5),0);art.addView(tag,tagPos);
            card.addView(art,match(isPortrait()?105:122));
            TextView name=label(RM11UiThemesV49059.NAMES[i],13,true);
            name.setGravity(Gravity.CENTER);
            card.addView(name,match(37));
            TextView state=label(chosen?"✓ النمط المعتمد":"اضغط للتفعيل",11,false);
            state.setGravity(Gravity.CENTER);
            state.setTextColor(chosen?RM11UiThemesV49059.accent(i):0xffbacadd);
            card.addView(state,match(29));
            card.setOnClickListener(v->{
                RM11UiThemesV49059.select(this,index);
                // Rebuild only this Android settings activity to preview the
                // selected animated background immediately; Wine is untouched.
                recreate();
            });
            GridLayout.LayoutParams gp=new GridLayout.LayoutParams();
            gp.width=dp(cell);gp.height=GridLayout.LayoutParams.WRAP_CONTENT;
            gp.setMargins(dp(4),dp(4),dp(4),dp(4));
            previews.addView(card,gp);
        }
        options.removeAllViews();
        int mode=RM11UiThemesV49059.orientation(this);
        LinearLayout modes=new LinearLayout(this);
        modes.setOrientation(LinearLayout.HORIZONTAL);
        String[] labels={"تلقائي ↻","عمودي ↕","أفقي ↔"};
        for(int j=0;j<3;j++){
            final int index=j;
            Button b=button(labels[j],mode==j?RM11UiThemesV49059.accent(current):0xff253142,
                v->{
                    if(RM11UiThemesV49059.orientation(this)==index)return;
                    RM11UiThemesV49059.setOrientation(this,index);
                    RM11UiThemesV49059.applyOrientation(this);
                    // If orientation did not change, reflect selection instantly.
                    render();
                });
            LinearLayout.LayoutParams bp=new LinearLayout.LayoutParams(0,dp(49),1);
            bp.setMargins(dp(3),0,dp(3),0);modes.addView(b,bp);
        }
        options.addView(modes,match(52));
        boolean motion=RM11UiThemesV49059.motion(this);
        options.addView(button(motion?
            "✦ تأثيرات الحركة والعمق: مفعّلة":"✦ تأثيرات الحركة والعمق: متوقفة",
            0xff263746,v->{
                RM11UiThemesV49059.setMotion(this,!RM11UiThemesV49059.motion(this));
                recreate();
            }),match(52));
    }
    /** Lightweight procedural depth/card motif, no copyrighted cover assets. */
    private final class MiniPreview extends View {
        private final int theme;
        private final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);
        MiniPreview(int n){super(RM11AppearanceActivity.this);theme=n;}
        @Override protected void onDraw(Canvas c){
            int w=getWidth(),h=getHeight();
            p.setColor(RM11UiThemesV49059.background(theme));
            c.drawRoundRect(new RectF(0,0,w,h),dp(12),dp(12),p);
            p.setColor(RM11UiThemesV49059.accent(theme));
            c.drawRoundRect(new RectF(dp(6),dp(7),w-dp(6),dp(11)),dp(3),dp(3),p);
            for(int j=0;j<3;j++){
                float x=dp(10)+j*(w-dp(20))/3f;
                float left=x, right=x+(w-dp(32))/3.4f;
                float top=(theme==3?dp(20)+j*dp(20):dp(24));
                float bottom=(theme==3?top+dp(17):h-dp(23));
                p.setColor((0xa0-j*0x20)<<24|(RM11UiThemesV49059.accent(theme)&0xffffff));
                c.drawRoundRect(new RectF(left,top,right,bottom),dp(6),dp(6),p);
                if(theme==2||theme==4){
                    p.setColor(0xaaffffff);
                    p.setStyle(Paint.Style.STROKE);p.setStrokeWidth(dp(1));
                    c.drawRoundRect(new RectF(left+dp(2),top+dp(2),right-dp(2),bottom-dp(2)),
                        dp(7),dp(7),p);
                    p.setStyle(Paint.Style.FILL);
                }
            }
            p.setColor(0x99ffffff);
            c.drawRoundRect(new RectF(dp(12),h-dp(16),w*.58f,h-dp(12)),
                dp(3),dp(3),p);
        }
    }
}
