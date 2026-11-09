package com.r4.qaflshamil

import android.app.Activity
import android.app.ActivityManager
import android.app.ActivityOptions
import android.app.AlertDialog
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class AdminReceiver: DeviceAdminReceiver()

class MainActivity: Activity() {
    private val prefs by lazy { getSharedPreferences("arabic_lock_settings", MODE_PRIVATE) }
    private val dpm by lazy { getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager }
    private val admin by lazy { ComponentName(this, AdminReceiver::class.java) }
    private val owner get() = dpm.isDeviceOwnerApp(packageName)
    private val active get() = prefs.getBoolean("active", false)
    private val single get() = prefs.getBoolean("single", true)
    private val selected get() = prefs.getStringSet("allowed", emptySet())?.toSet() ?: emptySet()
    private var adminOpen=false
    private lateinit var panel: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor=Color.rgb(16,36,57)
        window.navigationBarColor=Color.rgb(16,36,57)
        render()
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        adminOpen=false
        render()
    }
    override fun onPause() {
        super.onPause()
        if(active) adminOpen=false
    }
    override fun onResume() {
        super.onResume()
        if(active && owner) {
            try {
                val am=getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                if (am.lockTaskModeState==ActivityManager.LOCK_TASK_MODE_NONE) startLockTask()
            } catch (_: Exception) {}
        }
        render()
    }
    @Deprecated("Legacy system back")
    override fun onBackPressed() { adminOpen=false; render() }

    private fun toast(s:String) { Toast.makeText(this,s,Toast.LENGTH_LONG).show() }
    private fun pinSet() = prefs.contains("pin_hash")
    private fun hash(pin:String, salt:ByteArray):ByteArray {
        val chars=pin.toCharArray()
        val spec=PBEKeySpec(chars,salt,160_000,256)
        return try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded }
        finally { spec.clearPassword(); chars.fill('\u0000') }
    }
    private fun savePin(pin:String) {
        if(pin.length !in 6..12 || !pin.all { it in '0'..'9' }) { toast("استخدم 6 إلى 12 رقماً"); return }
        val salt=ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs.edit()
            .putString("pin_salt",Base64.getEncoder().encodeToString(salt))
            .putString("pin_hash",Base64.getEncoder().encodeToString(hash(pin,salt)))
            .putInt("failures",0).putLong("retry_after",0L).commit()
        adminOpen=true
        render()
    }
    private fun checkPin(pin:String):Boolean {
        val now=System.currentTimeMillis()
        val wait=prefs.getLong("retry_after",0L)-now
        if(wait>0L) { toast("حاول بعد "+((wait+999)/1000)+" ثانية"); return false }
        val ok=try {
            val salt=Base64.getDecoder().decode(prefs.getString("pin_salt",""))
            val expected=Base64.getDecoder().decode(prefs.getString("pin_hash",""))
            MessageDigest.isEqual(expected,hash(pin,salt))
        } catch (_: Exception) { false }
        if(ok) {
            prefs.edit().putInt("failures",0).putLong("retry_after",0).commit()
        } else {
            val count=prefs.getInt("failures",0)+1
            val cooldown=if(count>=5) (30_000L * (1L shl (count-5).coerceAtMost(5))).coerceAtMost(900_000L) else 0L
            prefs.edit().putInt("failures",count).putLong("retry_after",now+cooldown).commit()
            toast("الرمز غير صحيح")
        }
        return ok
    }
    private fun passField(hint:String)=EditText(this).apply {
        this.hint=hint
        inputType=InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        filters=arrayOf(android.text.InputFilter.LengthFilter(12))
        textDirection=View.TEXT_DIRECTION_RTL
    }
    private fun passDialog(title:String, onOk:(String)->Unit) {
        val field=passField("الرمز السري")
        val wrapper=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(35,12,35,12)
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            addView(field)
        }
        AlertDialog.Builder(this).setTitle(title).setView(wrapper)
            .setNegativeButton("إلغاء",null)
            .setPositiveButton("تأكيد") { _,_->onOk(field.text.toString()) }.show()
    }
    private fun createPin() {
        val a=passField("رمز جديد (6 إلى 12 رقم)")
        val b=passField("تأكيد الرمز")
        val wrapper=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(35,16,35,16)
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            addView(a); addView(b)
        }
        AlertDialog.Builder(this).setTitle("إنشاء رمز المشرف").setView(wrapper)
            .setNegativeButton("رجوع",null).setPositiveButton("حفظ") { _,_->
                val value=a.text.toString()
                if(value!=b.text.toString()) toast("الرمزان غير متطابقين")
                else savePin(value)
            }.show()
    }
    private fun unlockAdmin() { passDialog("أدخل رمز المشرف") { if(checkPin(it)) { adminOpen=true; render() } } }

    private var section=0
    private val bg=Color.rgb(245,248,252)
    private val navy=Color.rgb(18,36,60)
    private val deep=Color.rgb(12,28,49)
    private val teal=Color.rgb(0,157,143)
    private val lightTeal=Color.rgb(229,247,245)
    private val muted=Color.rgb(107,124,146)
    private val border=Color.rgb(225,234,242)
    private fun dp(v:Int):Int=(v*resources.displayMetrics.density+0.5f).toInt()
    private fun shape(c:Int,rad:Int=18,stroke:Int?=null)=android.graphics.drawable.GradientDrawable().apply {
        setColor(c);cornerRadius=dp(rad).toFloat()
        if(stroke!=null)setStroke(dp(1),stroke)
    }
    private fun label(host:LinearLayout,s:String,size:Float=16f,bold:Boolean=false,color:Int=navy,
                      marginTop:Int=0,marginBottom:Int=0):TextView {
        val item=TextView(this).apply {
            text=s; textSize=size;setTextColor(color)
            gravity=Gravity.RIGHT or Gravity.CENTER_VERTICAL
            textDirection=View.TEXT_DIRECTION_RTL
            setLineSpacing(dp(2).toFloat(),1f)
            if(bold)setTypeface(null,android.graphics.Typeface.BOLD)
        }
        host.addView(item,LinearLayout.LayoutParams(-1,-2).apply {
            topMargin=dp(marginTop);bottomMargin=dp(marginBottom)
        })
        return item
    }
    private fun padBox(host:LinearLayout,color:Int=Color.WHITE,outline:Boolean=true):LinearLayout {
        val card=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(17),dp(17),dp(17),dp(17))
            background=shape(color,20,if(outline) border else null)
            elevation=dp(2).toFloat()
        }
        host.addView(card,LinearLayout.LayoutParams(-1,-2).apply { bottomMargin=dp(14) })
        return card
    }
    private fun topButton(host:LinearLayout,text:String,primary:Boolean=true,click:()->Unit) {
        val v=TextView(this).apply {
            this.text=text;textSize=16f
            gravity=Gravity.CENTER
            setTypeface(null,android.graphics.Typeface.BOLD)
            setTextColor(if(primary) Color.WHITE else navy)
            background=shape(if(primary) teal else lightTeal,15)
            minHeight=dp(54)
            isClickable=true;isFocusable=true
            setOnClickListener { click() }
        }
        host.addView(v,LinearLayout.LayoutParams(-1,dp(54)).apply { topMargin=dp(9) })
    }
    private fun inlineRow(host:LinearLayout,title:String,detail:String,emoji:String,click:()->Unit) {
        val wrap=LinearLayout(this).apply {
            orientation=LinearLayout.HORIZONTAL
            gravity=Gravity.CENTER_VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(12),dp(12),dp(12),dp(12))
            background=shape(Color.WHITE,16,border)
            isClickable=true; setOnClickListener { click() }
        }
        val symbol=TextView(this).apply {
            text=emoji;textSize=23f;gravity=Gravity.CENTER
            background=shape(lightTeal,12)
        }
        wrap.addView(symbol,LinearLayout.LayoutParams(dp(48),dp(48)).apply { marginEnd=dp(12) })
        val mid=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
        label(mid,title,15.5f,true,navy)
        label(mid,detail,12.5f,false,muted,4,0)
        wrap.addView(mid,LinearLayout.LayoutParams(0,-2,1f))
        val arrow=TextView(this).apply { text="‹";textSize=27f;setTextColor(muted) }
        wrap.addView(arrow)
        host.addView(wrap,LinearLayout.LayoutParams(-1,-2).apply { bottomMargin=dp(10) })
    }
    private fun header(root:LinearLayout,subtitle:String) {
        val bar=LinearLayout(this).apply {
            orientation=LinearLayout.HORIZONTAL
            gravity=Gravity.CENTER_VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(20),dp(16),dp(20),dp(16))
            setBackgroundColor(Color.WHITE)
        }
        val logo=android.widget.ImageView(this).apply {
            setImageResource(com.r4.qaflshamil.R.drawable.ic_launcher)
            scaleType=android.widget.ImageView.ScaleType.FIT_CENTER
        }
        bar.addView(logo,LinearLayout.LayoutParams(dp(52),dp(52)).apply { marginEnd=dp(12) })
        val heading=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
        label(heading,"القفل الشامل",20f,true,deep)
        label(heading,subtitle,12f,false,muted,3,0)
        bar.addView(heading,LinearLayout.LayoutParams(0,-2,1f))
        root.addView(bar)
        val line=View(this).apply { setBackgroundColor(border) }
        root.addView(line,LinearLayout.LayoutParams(-1,dp(1)))
    }
    private fun nav(root:LinearLayout) {
        val labels=arrayOf("الرئيسية","التطبيقات","الحماية")
        val signs=arrayOf("⌂","▦","♜")
        val row=LinearLayout(this).apply {
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(Color.WHITE);setPadding(dp(10),dp(9),dp(10),dp(7))
        }
        for(i in labels.indices){
            val chosen=section==i
            val node=LinearLayout(this).apply {
                orientation=LinearLayout.VERTICAL
                gravity=Gravity.CENTER
                setPadding(0,dp(5),0,dp(5))
                background=shape(if(chosen)lightTeal else Color.WHITE,12)
                isClickable=true;setOnClickListener { section=i;render() }
            }
            label(node,signs[i],25f,true,if(chosen)teal else muted).apply {gravity=Gravity.CENTER}
            label(node,labels[i],12f,chosen,if(chosen)teal else muted,2,0).apply {gravity=Gravity.CENTER}
            row.addView(node,LinearLayout.LayoutParams(0,dp(66),1f))
        }
        root.addView(View(this).apply{setBackgroundColor(border)},LinearLayout.LayoutParams(-1,dp(1)))
        root.addView(row,LinearLayout.LayoutParams(-1,-2))
    }
    private fun render() {
        val root=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(bg)
            fitsSystemWindows=true
        }
        setContentView(root)
        header(root,when {
            !pinSet()->"ابدأ إعداد الحماية بسهولة"
            active && !adminOpen->"مساحة التطبيقات المسموحة"
            !adminOpen->"لوحة التحكم محمية"
            section==1->"حدد التطبيقات المسموحة"
            section==2->"إعدادات الأمان والرمز"
            else->"تحكّم بجهازك بطريقتك"
        })
        val scroll=ScrollView(this).apply {
            isFillViewport=true
            clipToPadding=false
        }
        panel=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(18),dp(22),dp(18),dp(30))
        }
        scroll.addView(panel)
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        when {
            !pinSet()->renderWelcome()
            active && !adminOpen->renderKiosk()
            !adminOpen->renderGate()
            else->{
                when(section) {
                    1->renderPicker()
                    2->renderSecurity()
                    else->renderHome()
                }
                nav(root)
            }
        }
    }
    private fun renderWelcome() {
        val card=padBox(panel,deep,false)
        label(card,"حماية أبسط. تحكم أكبر.",25f,true,Color.WHITE,4,8)
        label(card,"اختَر تطبيقاً واحداً أو عدة تطبيقات، واحمِ خياراتك برمز خاص بك.",15f,false,Color.rgb(201,222,235),2,14)
        label(panel,"أهلاً بيك 👋",23f,true,navy,20,8)
        label(panel,"أول خطوة: إنشاء رمز المشرف. هذا الرمز يسمح لك بتغيير الإعدادات وإيقاف الحماية لاحقاً.",15f,false,muted,0,20)
        val features=padBox(panel)
        label(features,"✓ واجهة عربية بالكامل",16f,true,navy,0,14)
        label(features,"✓ وضع تطبيق واحد أو عدة تطبيقات",15f,false,muted,0,14)
        label(features,"✓ التحكم بالوصول عبر رمز سري",15f,false,muted,0,14)
        label(features,"✓ حماية Kiosk عند توفر إدارة الجهاز",15f,false,muted)
        topButton(panel,"إنشاء رمز المشرف",true){createPin()}
        label(panel,"ملاحظة: منع الحذف الكامل يحتاج إعداد Device Owner منفصل، ولا يتفعّل بمجرد تثبيت التطبيق.",13f,false,muted,15,0)
    }
    private fun renderGate() {
        val c=padBox(panel)
        label(c,"🔐 إعداداتك خاصة",23f,true,navy,3,12)
        label(c,"أدخل رمز المشرف للوصول إلى اختيار التطبيقات، ووضع القفل، وإعدادات الأمان.",16f,false,muted,0,16)
        topButton(c,"فتح لوحة التحكم",true){unlockAdmin()}
        label(panel,if(owner) "✓ إدارة الجهاز متاحة" else "◌ إدارة الجهاز الكاملة غير مفعلة",14f,false,muted,17,4)
    }
    private fun renderHome() {
        val hero=padBox(panel,deep,false)
        label(hero,if(active)"الحماية مفعّلة" else "جاهز لترتيب التطبيقات",22f,true,Color.WHITE,1,9)
        label(hero,if(active)"التطبيقات خارج القائمة المسموحة مقيدة بوضع Kiosk." else "حدد التطبيقات ثم فعّل الحماية عندما يجهز وضع إدارة الجهاز.",14f,false,Color.rgb(194,220,228),0,8)
        val state=label(hero,if(owner)"✓ إدارة الجهاز متاحة" else "○ إدارة الجهاز غير مفعّلة",14f,true,if(owner)Color.rgb(135,245,202) else Color.rgb(255,208,142),10,2)
        state.gravity=Gravity.RIGHT
        val overview=padBox(panel)
        label(overview,"نظرة سريعة",19f,true,navy,0,12)
        val stat=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;layoutDirection=View.LAYOUT_DIRECTION_RTL}
        fun metric(value:String,caption:String) {
            val v=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;gravity=Gravity.CENTER;background=shape(bg,15)}
            label(v,value,26f,true,teal,0,2).gravity=Gravity.CENTER
            label(v,caption,13f,false,muted).gravity=Gravity.CENTER
            stat.addView(v,LinearLayout.LayoutParams(0,dp(85),1f).apply{marginEnd=dp(5)})
        }
        metric(selected.size.toString(),"تطبيق مسموح")
        metric(if(single)"واحد" else "متعدد","وضع التشغيل")
        overview.addView(stat)
        label(panel,"طريقة القفل",20f,true,navy,12,12)
        inlineRow(panel,if(single)"تطبيق واحد فقط" else "عدة تطبيقات","اضغط للتبديل بين الوضعين","▣"){
            if(active){toast("أوقف الحماية قبل تعديل الوضع");return@inlineRow}
            prefs.edit().putBoolean("single",!single).commit()
            if(!single && selected.size>1) prefs.edit().putStringSet("allowed",setOf(selected.first())).commit()
            render()
        }
        inlineRow(panel,"التطبيقات المسموحة","تم اختيار "+selected.size+" تطبيق","▦"){
            section=1;render()
        }
        if(active) {
            topButton(panel,"إيقاف الحماية",false){
                passDialog("أدخل رمز المشرف لإيقاف القفل") { if(checkPin(it)) deactivate() }
            }
        } else {
            topButton(panel,"تفعيل القفل الشامل",true){ activate() }
        }
        if(!owner) label(panel,"لا يمكن تفعيل الحماية القوية قبل إعداد Device Owner. انتقل إلى صفحة الحماية لمعرفة الحالة.",13f,false,muted,16,0)
    }
    private fun renderPicker() {
        label(panel,"اختَر اللي تحتاجه فقط",22f,true,navy,0,7)
        label(panel,"التطبيقات المحددة تبقى مسموحة وقت القفل. تقدر تغيّرها قبل تشغيل الحماية.",14f,false,muted,0,13)
        val mode=padBox(panel)
        label(mode,"الوضع الحالي",13f,false,muted)
        label(mode,if(single)"تطبيق واحد" else "عدة تطبيقات",19f,true,navy,5,5)
        topButton(mode,if(single)"التبديل إلى عدة تطبيقات" else "التبديل إلى تطبيق واحد",false) {
            if(active){toast("أوقف الحماية أولاً");return@topButton}
            prefs.edit().putBoolean("single",!single).commit()
            if(!single && selected.size>1) prefs.edit().putStringSet("allowed",setOf(selected.first())).commit()
            render()
        }
        label(panel,"التطبيقات الموجودة على هاتفك",19f,true,navy,10,6)
        val counter=label(panel,"المحدد حالياً: "+selected.size,14f,false,teal,0,13)
        if(active) {
            label(panel,"أوقف الحماية أولاً حتى تعدل القائمة.",14f,false,muted)
            return
        }
        val finder=EditText(this).apply {
            hint="ابحث عن تطبيق..."
            textSize=15f
            setSingleLine(true)
            textDirection=View.TEXT_DIRECTION_RTL
            setPadding(dp(16),dp(12),dp(16),dp(12))
            background=shape(Color.WHITE,15,border)
        }
        panel.addView(finder,LinearLayout.LayoutParams(-1,dp(52)).apply{bottomMargin=dp(14)})
        val list=apps()
        if(list.isEmpty()){label(panel,"ما لقينا تطبيقات قابلة للتشغيل.",15f,false,muted);return}
        val listHost=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        panel.addView(listHost)
        val visibleRows=mutableListOf<Pair<String,View>>()
        list.forEach { (appName,pkg)->
            val row=LinearLayout(this).apply {
                orientation=LinearLayout.HORIZONTAL
                gravity=Gravity.CENTER_VERTICAL
                layoutDirection=View.LAYOUT_DIRECTION_RTL
                setPadding(dp(12),dp(12),dp(12),dp(12))
                background=shape(Color.WHITE,15,border)
            }
            val icon=android.widget.ImageView(this).apply {
                try { setImageDrawable(packageManager.getApplicationIcon(pkg)) } catch (_:Exception) { setImageResource(R.drawable.ic_launcher) }
                scaleType=android.widget.ImageView.ScaleType.FIT_CENTER
            }
            row.addView(icon,LinearLayout.LayoutParams(dp(44),dp(44)).apply{marginEnd=dp(12)})
            val name=TextView(this).apply {
                text=appName;textSize=15f;setTextColor(navy)
                gravity=Gravity.RIGHT or Gravity.CENTER_VERTICAL
                setTypeface(null,android.graphics.Typeface.BOLD)
                maxLines=2
            }
            row.addView(name,LinearLayout.LayoutParams(0,-2,1f))
            val mark=TextView(this).apply {
                text=if(pkg in selected)"✓" else "+"
                textSize=20f;gravity=Gravity.CENTER
                setTextColor(if(pkg in selected) Color.WHITE else teal)
                background=shape(if(pkg in selected)teal else lightTeal,11)
            }
            row.addView(mark,LinearLayout.LayoutParams(dp(34),dp(34)).apply{marginStart=dp(10)})
            row.setOnClickListener {
                val next=if(single)setOf(pkg) else selected.toMutableSet().apply {
                    if(pkg in this)remove(pkg) else add(pkg)
                }
                if(next.isEmpty()) { toast("يجب اختيار تطبيق واحد على الأقل");return@setOnClickListener }
                prefs.edit().putStringSet("allowed",next).commit()
                if(single) render()
                else {
                    val chosen=pkg in next
                    mark.text=if(chosen)"✓" else "+"
                    mark.setTextColor(if(chosen)Color.WHITE else teal)
                    mark.background=shape(if(chosen)teal else lightTeal,11)
                    counter.text="المحدد حالياً: "+next.size
                }
            }
            listHost.addView(row,LinearLayout.LayoutParams(-1,-2).apply{bottomMargin=dp(8)})
            visibleRows.add(appName.lowercase() to row)
        }
        finder.addTextChangedListener(object:android.text.TextWatcher{
            override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){}
            override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){
                val q=s?.toString()?.trim()?.lowercase().orEmpty()
                visibleRows.forEach{(name,row)->row.visibility=if(name.contains(q))View.VISIBLE else View.GONE}
            }
            override fun afterTextChanged(e:android.text.Editable?){}
        })
    }
    private fun renderSecurity() {
        label(panel,"حماية الجهاز",23f,true,navy,0,7)
        label(panel,"هنا تشوف مستوى الحماية وتتحكم بالرمز السري.",14f,false,muted,0,17)
        val pin=padBox(panel)
        label(pin,"رمز المشرف",18f,true,navy,0,7)
        label(pin,"رمزك محفوظ محلياً، وما نرسله لأي جهة.",14f,false,muted,0,12)
        topButton(pin,"تغيير الرمز السري",false){
            passDialog("تحقق من الرمز الحالي") { if(checkPin(it)) createPin() }
        }
        val state=padBox(panel)
        label(state,"مستوى حماية الجهاز",18f,true,navy,0,9)
        label(state,if(owner)"✓ إدارة الجهاز الكاملة مفعلة" else "○ إدارة الجهاز الكاملة غير مفعلة",
            16f,true,if(owner)teal else Color.rgb(181,115,43),0,12)
        label(state,if(owner)"يمكن للتطبيق استخدام وضع Lock Task الرسمي عند تفعيله." else
            "تثبيت APK وحده ما يمنع حذف التطبيق أو فتح التطبيقات الأخرى. يحتاج إعداد Device Owner منفصل.",
            14f,false,muted,0,11)
        if(owner && !active) {
            topButton(state,"إلغاء إدارة الجهاز (اختبار فقط)",false){
                passDialog("رمز المشرف لإلغاء الإدارة") { if(checkPin(it)) releaseOwner() }
            }
        }
        val info=padBox(panel,lightTeal,false)
        label(info,"تنبيه مهم",17f,true,navy,0,8)
        label(info,"لا تفعّل وضع إدارة الجهاز على هاتفك الأساسي قبل النسخ الاحتياطي والتجربة على جهاز آخر. حتى الإدارة الكاملة ما تمنع إعادة ضبط المصنع أو كل طرق الاسترداد.",14f,false,navy)
        topButton(panel,"قفل لوحة التحكم بالرمز",false){adminOpen=false;section=0;render()}
    }
    private fun renderKiosk() {
        val card=padBox(panel,deep,false)
        label(card,"🔒 الوضع المحمي",22f,true,Color.WHITE,3,8)
        label(card,"هذي التطبيقات فقط ضمن قائمتك المسموحة.",15f,false,Color.rgb(194,220,228))
        label(panel,"التطبيقات المتاحة",20f,true,navy,17,15)
        val names=apps().associateBy{it.second}
        selected.sorted().forEach{pkg->
            val pair=names[pkg]
            inlineRow(panel,pair?.first ?: pkg,"اضغط لفتح التطبيق","↗"){launch(pkg)}
        }
        topButton(panel,"إعدادات المشرف 🔑",false){unlockAdmin()}
    }
    private fun apps():List<Pair<String,String>> {
        val intent=Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(intent,PackageManager.MATCH_ALL)
            .filter { it.activityInfo.packageName!=packageName }
            .map { it.loadLabel(packageManager).toString() to it.activityInfo.packageName }
            .distinctBy { it.second }.sortedBy { it.first.lowercase() }
    }
    private fun pickApps() {
        val list=apps()
        if(list.isEmpty()) { toast("لم تظهر تطبيقات قابلة للتشغيل"); return }
        val labels=list.map { it.first }.toTypedArray()
        if(single) {
            val checked=list.indexOfFirst { it.second in selected }
            AlertDialog.Builder(this).setTitle("اختر تطبيقاً واحداً")
                .setSingleChoiceItems(labels,checked) { dialog,n ->
                    prefs.edit().putStringSet("allowed",setOf(list[n].second)).commit()
                    dialog.dismiss();render()
                }.setNegativeButton("رجوع",null).show()
        } else {
            val picked=selected.toMutableSet()
            val checked=BooleanArray(list.size) { list[it].second in picked }
            AlertDialog.Builder(this).setTitle("اختر التطبيقات المسموحة")
                .setMultiChoiceItems(labels,checked) { _,index,isChecked ->
                    if(isChecked) picked.add(list[index].second) else picked.remove(list[index].second)
                }.setNegativeButton("إلغاء",null)
                .setPositiveButton("حفظ") { _,_->
                    if(picked.isEmpty()) toast("اختر تطبيقاً واحداً على الأقل")
                    else { prefs.edit().putStringSet("allowed",picked.toSet()).commit();render() }
                }.show()
        }
    }
    private fun activate() {
        if(!owner) { AlertDialog.Builder(this).setTitle("الإدارة غير مفعلة")
            .setMessage("لا يمكن تنفيذ قفل قوي بدون Device Owner. النسخة التجريبية لا تفرض قفلاً وهمياً.")
            .setPositiveButton("فهمت",null).show(); return }
        if(selected.isEmpty()) { toast("اختر تطبيقاً على الأقل"); return }
        AlertDialog.Builder(this).setTitle("تأكيد تفعيل القفل")
            .setMessage("استخدم هذا الخيار بعد اختبار فك القفل والاحتفاظ بنسخة احتياطية. قد يصعب إلغاء إدارة الجهاز.")
            .setNegativeButton("رجوع",null).setPositiveButton("تفعيل") { _,_->
                try {
                    selected.forEach { check(packageManager.getLaunchIntentForPackage(it)!=null) }
                    dpm.setLockTaskPackages(admin,(selected+packageName).toTypedArray())
                    val filter=IntentFilter(Intent.ACTION_MAIN).apply {
                        addCategory(Intent.CATEGORY_HOME); addCategory(Intent.CATEGORY_DEFAULT)
                    }
                    dpm.addPersistentPreferredActivity(admin,filter,ComponentName(this,MainActivity::class.java))
                    dpm.setLockTaskFeatures(admin,DevicePolicyManager.LOCK_TASK_FEATURE_HOME)
                    dpm.setUninstallBlocked(admin,packageName,true)
                    prefs.edit().putBoolean("active",true).commit()
                    adminOpen=false;render();startLockTask()
                    val am=getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                    check(am.lockTaskModeState==ActivityManager.LOCK_TASK_MODE_LOCKED)
                } catch (e:Exception) {
                    try { internalDeactivate() } catch (_:Exception) {}
                    toast("فشل تفعيل القفل: "+e.message);render()
                }
            }.show()
    }
    private fun launch(pkg:String) {
        if(!active || !owner || pkg !in selected || !dpm.isLockTaskPermitted(pkg)) { toast("التطبيق غير مصرح به");return }
        try {
            val intent=packageManager.getLaunchIntentForPackage(pkg) ?: error("غير قابل للتشغيل")
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent,ActivityOptions.makeBasic().apply { setLockTaskEnabled(true) }.toBundle())
        } catch(e:Exception) { toast("تعذر التشغيل: "+e.message) }
    }
    private fun internalDeactivate() {
        if(!owner) { prefs.edit().putBoolean("active",false).commit();return }
        dpm.setLockTaskPackages(admin,arrayOf(packageName))
        try { stopLockTask() } catch (_:Exception) {}
        dpm.clearPackagePersistentPreferredActivities(admin,packageName)
        dpm.setLockTaskFeatures(admin,DevicePolicyManager.LOCK_TASK_FEATURE_NONE)
        dpm.setUninstallBlocked(admin,packageName,false)
        dpm.setLockTaskPackages(admin,emptyArray())
        prefs.edit().putBoolean("active",false).commit()
    }
    private fun deactivate() {
        try { internalDeactivate(); toast("تم إيقاف الحماية"); render() }
        catch(e:Exception) { toast("تعذر الإيقاف: "+e.message) }
    }
    @Suppress("DEPRECATION")
    private fun releaseOwner() {
        AlertDialog.Builder(this).setTitle("فك إدارة الجهاز — تجريبي")
            .setMessage("قد يفشل فك الإدارة على بعض الأجهزة. لا تختبره على هاتفك الأساسي.")
            .setNegativeButton("إلغاء",null).setPositiveButton("فك الإدارة") { _,_->
                try {
                    if(active) error("أوقف القفل أولاً")
                    dpm.clearDeviceOwnerApp(packageName)
                    if(owner) error("رفض النظام فك الإدارة")
                    toast("تم فك إدارة الجهاز"); render()
                } catch(e:Exception) { toast("فشل فك الإدارة: "+e.message) }
            }.show()
    }
}