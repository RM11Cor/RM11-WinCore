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
import android.provider.Settings
import android.net.Uri
import android.accessibilityservice.AccessibilityServiceInfo
import android.view.accessibility.AccessibilityManager
import android.widget.ListView
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.graphics.drawable.Drawable
import android.graphics.Typeface
import android.os.Build
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import java.util.concurrent.Executors
import android.text.TextWatcher
import android.text.Editable
import android.widget.Filter
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class MainActivity: Activity() {
    companion object { @Volatile var foreground=false }
    private val prefs by lazy { getSharedPreferences("arabic_lock_settings", MODE_PRIVATE) }
    private val active get() = prefs.getBoolean("active", false)
    private val allowOnly get() = prefs.getInt("mode",0)==0
    private val selected get() = prefs.getStringSet(if(allowOnly)"allow_packages" else "block_packages",emptySet())?.toSet() ?: emptySet()
    private var cachedApps:List<Pair<String,String>>?=null
    private val loading=Executors.newSingleThreadExecutor()
    private val iconCache=android.util.LruCache<String,Drawable>(48)
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
        foreground=false
        super.onPause()
        if(active) adminOpen=false
    }
    override fun onResume() {
        super.onResume()
        foreground=true
        GuardService.instance?.hideOverlay()
        render()
    }
    override fun onDestroy(){
        loading.shutdown()
        super.onDestroy()
    }
    @Deprecated("Legacy system back")
    override fun onBackPressed() { adminOpen=false; render() }

    private fun toast(s:String){
        if(android.os.Looper.myLooper()==android.os.Looper.getMainLooper())
            Toast.makeText(this,s,Toast.LENGTH_SHORT).show()
        else runOnUiThread{Toast.makeText(this,s,Toast.LENGTH_SHORT).show()}
    }
    private fun pinSet() = prefs.contains("pin_hash")
    private fun hash(pin:String, salt:ByteArray):ByteArray {
        val chars=pin.toCharArray()
        val spec=PBEKeySpec(chars,salt,160_000,256)
        return try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded }
        finally { spec.clearPassword(); chars.fill('\u0000') }
    }
    private fun savePin(pin:String) {
        if(pin.length !in 6..12 || !pin.all{it in '0'..'9'}) {
            toast("الرمز لازم يكون من ٦ إلى ١٢ رقم");return
        }
        loading.execute {
            val salt=ByteArray(16).also{SecureRandom().nextBytes(it)}
            val digest=hash(pin,salt)
            val fresh=!prefs.contains("recovery_hash")
            val code=if(fresh) (1..16).joinToString("") { SecureRandom().nextInt(10).toString() } else ""
            val editor=prefs.edit()
                .putString("pin_salt",Base64.getEncoder().encodeToString(salt))
                .putString("pin_hash",Base64.getEncoder().encodeToString(digest))
                .putInt("failures",0).putLong("retry_after",0L)
            if(fresh){
                val rsalt=ByteArray(16).also{SecureRandom().nextBytes(it)}
                editor.putString("recovery_salt",Base64.getEncoder().encodeToString(rsalt))
                    .putString("recovery_hash",Base64.getEncoder().encodeToString(hash(code,rsalt)))
            }
            editor.commit()
            runOnUiThread {
                adminOpen=true
                render()
                if(fresh)AlertDialog.Builder(this).setTitle("رمز الاستعادة الاحتياطي")
                    .setMessage("احفظ هذا الرمز بمكان آمن خارج هاتفك. يظهر مرة واحدة فقط، وتحتاجه إذا نسيت رمز المشرف:\n\n"+code+"\n\nحالياً ماكو ربط بحساب Google أو Apple لاستعادة الرمز.")
                    .setPositiveButton("حفظته",null).setCancelable(false).show()
            }
        }
    }
    private fun verifyPinAsync(code:String,ok:()->Unit) {
        loading.execute {
            val good=checkPin(code)
            runOnUiThread{if(good)ok()}
        }
    }
    private fun recoveryDialog(){
        val field=EditText(this).apply{
            hint="رمز الاستعادة الاحتياطي المكوّن من ١٦ رقم"
            inputType=InputType.TYPE_CLASS_NUMBER;setSingleLine(true)
        }
        AlertDialog.Builder(this).setTitle("نسيت رمز المشرف؟")
            .setMessage("تگدر تستخدم رمز الاستعادة اللي ظهر عند إنشاء الرمز أول مرة. ما نقدر نستعيده عن طريق Google أو Apple بدون ربط حساب آمن.")
            .setView(field).setNegativeButton("إلغاء",null)
            .setPositiveButton("تحقق"){_,_->
                val candidate=field.text.toString()
                loading.execute{
                    val valid=try{
                        val salt=Base64.getDecoder().decode(prefs.getString("recovery_salt",""))
                        val hashValue=Base64.getDecoder().decode(prefs.getString("recovery_hash",""))
                        MessageDigest.isEqual(hash(candidate,salt),hashValue)
                    }catch(_:Exception){false}
                    runOnUiThread {
                        if(valid)createPin() else toast("رمز الاستعادة غير صحيح")
                    }
                }
            }.show()
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
    private fun unlockAdmin(){
        if(prefs.getBoolean("bio_enabled",false) && biometricAvailable()){
            try{
                val b=BiometricPrompt.Builder(this).setTitle("القفل الشامل")
                    .setSubtitle("افتح لوحة التحكم ببصمة الجهاز أو الوجه")
                    .setNegativeButton("استخدام الرمز",mainExecutor){_,_->askAdminPin()}
                if(Build.VERSION.SDK_INT>=30)b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                b.build().authenticate(CancellationSignal(),mainExecutor,
                    object:BiometricPrompt.AuthenticationCallback(){
                        override fun onAuthenticationSucceeded(result:BiometricPrompt.AuthenticationResult){
                            adminOpen=true;render()
                        }
                        override fun onAuthenticationError(errorCode:Int,errString:CharSequence){
                            if(errorCode!=13)toast("استخدم الرمز إذا ما اشتغل التحقق")
                        }
                    })
            }catch(_:Exception){askAdminPin()}
        } else askAdminPin()
    }
    private fun askAdminPin(){
        passDialog("أدخل رمز المشرف"){code->
            verifyPinAsync(code){adminOpen=true;render()}
        }
    }
    private fun biometricAvailable():Boolean=try{
        val bm=getSystemService(BIOMETRIC_SERVICE) as BiometricManager
        if(Build.VERSION.SDK_INT>=30)bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)==BiometricManager.BIOMETRIC_SUCCESS
        else @Suppress("DEPRECATION") bm.canAuthenticate()==BiometricManager.BIOMETRIC_SUCCESS
    }catch(_:Exception){false}
    private fun serviceEnabled():Boolean=try {
        val am=getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).any{
            it.resolveInfo.serviceInfo.packageName==packageName &&
                it.resolveInfo.serviceInfo.name==GuardService::class.java.name
        } || GuardService.instance!=null
    }catch(_:Exception){GuardService.instance!=null}
    private fun goToSettings(action:String){
        try{startActivity(Intent(action))}
        catch(_:Exception){startActivity(Intent(Settings.ACTION_SETTINGS))}
    }
    private fun requestAccessibility(){
        if(!prefs.getBoolean("access_disclosure",false)){
            AlertDialog.Builder(this)
                .setTitle("إذن مراقبة التطبيقات")
                .setMessage("حتى ينقفل التطبيق المطلوب، القفل الشامل يحتاج إمكانية الوصول. راح يستخدم فقط اسم التطبيق الظاهر حتى يقرر يعرض شاشة الرمز. ما يقرأ رسائلك ولا كلمات السر، وما يرسل بيانات للإنترنت.\n\nأندرويد يحتاج موافقتك اليدوية. تگدر تلغيها بأي وقت من الإعدادات.")
                .setNegativeButton("مو هسه",null)
                .setPositiveButton("أوافق وأفتح الإعدادات"){_,_->
                    prefs.edit().putBoolean("access_disclosure",true).apply()
                    goToSettings(Settings.ACTION_ACCESSIBILITY_SETTINGS)
                }.show()
        } else goToSettings(Settings.ACTION_ACCESSIBILITY_SETTINGS)
    }
    private fun changeMode(toAllow:Boolean){
        if(allowOnly==toAllow)return
        prefs.edit().putInt("mode",if(toAllow)0 else 1).apply()
        GuardService.instance?.refresh()
        render()
    }
    private fun toggleProtection(){
        if(active){
            passDialog("رمز المشرف لإيقاف القفل"){code->
                verifyPinAsync(code){
                    prefs.edit().putBoolean("active",false).apply()
                    GuardService.instance?.refresh()
                    toast("تم إيقاف القفل")
                    render()
                }
            }
        } else{
            if(selected.isEmpty()){toast("اختر تطبيقاً واحداً على الأقل");section=1;render();return}
            if(!serviceEnabled()){
                AlertDialog.Builder(this).setTitle("نحتاج إذن أولاً")
                    .setMessage("حتى تنقفل التطبيقات فعلياً، لازم تسمح بخدمة مراقبة التطبيقات من إعدادات إمكانية الوصول.")
                    .setNegativeButton("رجوع",null)
                    .setPositiveButton("اذهب للإعدادات"){_,_->requestAccessibility()}.show()
                return
            }
            prefs.edit().putBoolean("active",true).apply()
            GuardService.instance?.refresh()
            toast("تم تشغيل قفل التطبيقات")
            render()
        }
    }

    private var section=0
    private val bg=Color.rgb(245,248,252)
    private val navy=Color.rgb(18,36,60)
    private val deep=Color.rgb(12,28,49)
    private val teal=Color.rgb(37,132,229)
    private val lightTeal=Color.rgb(233,241,255)
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
            background=if(primary)android.graphics.drawable.GradientDrawable(
                android.graphics.drawable.GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(Color.rgb(31,163,239),Color.rgb(118,77,227))
            ).apply{cornerRadius=dp(15).toFloat()} else shape(lightTeal,15)
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
            active && !adminOpen->"الحماية شغّالة"
            !adminOpen->"لوحة التحكم محمية"
            section==1->"إضافة أو إزالة التطبيقات"
            section==2->"الأذونات والحماية والدعم"
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
            active && !adminOpen->renderGate()
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
        label(card,"مساحة آمنة، بطريقتك.",26f,true,Color.WHITE,4,10)
        label(card,"تختار المسموح أو تحدد التطبيقات اللي تريد تقفلها. واجهة عربية بسيطة، وبدون حساب أو تسجيل.",15f,false,Color.rgb(201,222,235),0,12)
        label(panel,"خلّينا نبدأ 🔐",23f,true,navy,16,8)
        label(panel,"أنشئ رمز المشرف حتى تگدر تغيّر القوائم وتشغل أو توقف القفل.",15f,false,muted,0,14)
        val c=padBox(panel)
        label(c,"◉ اسمح لهذني فقط",17f,true,navy,0,8)
        label(c,"كل تطبيق تختاره يبقى مفتوح، والبقية تظهر إلها شاشة القفل.",14f,false,muted,0,16)
        label(c,"◉ اقفل هذني فقط",17f,true,navy,0,8)
        label(c,"تحدد التطبيقات اللي ما تريدها تنفتح بدون رمز.",14f,false,muted)
        topButton(panel,"ابدأ وأنشئ رمزك",true){createPin()}
        label(panel,"التطبيق يحتاج إذن إمكانية الوصول بموافقتك حتى ينفّذ القفل. بعدها تختار اللي يناسبك.",13f,false,muted,15,0)
    }

    private fun renderGate() {
        val c=padBox(panel,deep,false)
        label(c,if(active)"● القفل مفعّل" else "○ القفل غير مفعّل",18f,true,
            if(active)Color.rgb(106,231,220) else Color.WHITE,2,13)
        label(c,"🔐 إعداداتك محمية",23f,true,Color.WHITE,3,12)
        label(c,"افتح لوحة التحكم بالرمز السري أو تحقق الجهاز إذا فعّلته.",15f,false,Color.rgb(207,222,244),0,12)
        topButton(c,"فتح لوحة التحكم",true){unlockAdmin()}
        topButton(panel,"نسيت الرمز؟ استخدم رمز الاستعادة",false){recoveryDialog()}
        label(panel,if(serviceEnabled())"✓ إذن مراقبة التطبيقات مفعّل" else
            "⚠ إذن مراقبة التطبيقات غير مفعّل؛ القفل ما يشتغل بدونه",
            14f,false,if(serviceEnabled())teal else Color.rgb(174,93,65),18,3)
        if(!serviceEnabled())topButton(panel,"منح الإذن الآن",true){requestAccessibility()}
    }

    private fun renderHome() {
        val hero=padBox(panel,deep,false)
        label(hero,if(active)"القفل شغّال الآن" else "قفل يناسب استخدامك",23f,true,Color.WHITE,2,9)
        label(hero,if(active)"كل محاولة لفتح تطبيق مقفول راح تظهر إلها شاشة الرمز." else
            "اختَر الوضع المناسب، حدد التطبيقات، واضغط تشغيل.",15f,false,Color.rgb(195,218,233),0,8)
        label(hero,if(serviceEnabled())"✓ إذن المراقبة مفعّل" else "◌ باقي إذن مراقبة التطبيقات",
            13f,true,if(serviceEnabled())Color.rgb(108,235,199) else Color.rgb(255,206,145),10)
        label(panel,"شنو تريد تسوي؟",21f,true,navy,16,12)
        val m=padBox(panel)
        inlineRow(m,"اسمح لهذني فقط", "المسموح: "+prefs.getStringSet("allow_packages",emptySet()).orEmpty().size+" تطبيق","✓") {
            changeMode(true)
        }
        inlineRow(m,"اقفل هذني فقط", "المقفول: "+prefs.getStringSet("block_packages",emptySet()).orEmpty().size+" تطبيق","✕") {
            changeMode(false)
        }
        label(panel,if(allowOnly)"الوضع المختار: اسمح لهذني فقط" else "الوضع المختار: اقفل هذني فقط",
            16f,true,teal,2,12)
        val overview=padBox(panel)
        label(overview,"اختياراتك محفوظة حتى لو تبدّل الوضع",16f,true,navy,0,8)
        label(overview,"حالياً محدد "+selected.size+" تطبيق. اضغط على قائمة التطبيقات حتى تضيف أو تلغي أي برنامج.",14f,false,muted,0,10)
        topButton(overview,"افتح قائمة التطبيقات",false){section=1;render()}
        topButton(panel,if(active)"إيقاف القفل" else "تشغيل القفل الآن",true){toggleProtection()}
        if(!serviceEnabled())topButton(panel,"السماح بمراقبة التطبيقات",false){requestAccessibility()}
        label(panel,"بعض واجهات النظام ما يكدر أي تطبيق عادي يغلقها بالكامل. القفل يعتمد على استمرار خدمة إمكانية الوصول.",13f,false,muted,16)
    }

    private fun renderPicker() {
        label(panel,"اختَر التطبيقات",23f,true,navy,0,7)
        label(panel,"واضح وسريع: إضافة أو إلغاء، وكل وضع يحتفظ بقائمته وحده.",14f,false,muted,0,13)
        val modes=padBox(panel)
        label(modes,"نوع القفل",15f,true,navy,0,10)
        topButton(modes,"✓ اسمح لهذني فقط"+if(allowOnly)" — مختار" else "",allowOnly){changeMode(true)}
        topButton(modes,"✕ اقفل هذني فقط"+if(!allowOnly)" — مختار" else "",!allowOnly){changeMode(false)}
        label(panel,if(allowOnly)"التطبيقات المسموحة" else "التطبيقات المقفولة",
            19f,true,navy,10,6)
        val counter=label(panel,"المحدد حالياً: "+selected.size,14f,false,teal,0,13)
        val search=EditText(this).apply{
            hint="ابحث باسم التطبيق…";setSingleLine(true)
            textSize=15f;textDirection=View.TEXT_DIRECTION_RTL
            setPadding(dp(16),dp(12),dp(16),dp(12))
            background=shape(Color.WHITE,15,border)
        }
        panel.addView(search,LinearLayout.LayoutParams(-1,dp(52)).apply{bottomMargin=dp(14)})
        val holder=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        panel.addView(holder,LinearLayout.LayoutParams(-1,-2))
        label(holder,"جاري ترتيب التطبيقات…",14f,false,muted)
        fun show(items:List<Pair<String,String>>){
            if(isFinishing||isDestroyed||section!=1 || !adminOpen)return
            holder.removeAllViews()
            val listView=ListView(this).apply{
                divider=null
                cacheColorHint=Color.TRANSPARENT
                setBackgroundColor(bg)
                isVerticalScrollBarEnabled=true
                overScrollMode=View.OVER_SCROLL_NEVER
            }
            val filtered=items.toMutableList()
            val adapter=object:android.widget.BaseAdapter(){
                override fun getCount()=filtered.size
                override fun getItem(position:Int)=filtered[position]
                override fun getItemId(position:Int)=position.toLong()
                override fun getView(position:Int,convertView:View?,parent:android.view.ViewGroup):View {
                    val data=filtered[position]
                    val row=(convertView as? LinearLayout) ?: LinearLayout(this@MainActivity).apply {
                        orientation=LinearLayout.HORIZONTAL
                        gravity=Gravity.CENTER_VERTICAL
                        layoutDirection=View.LAYOUT_DIRECTION_RTL
                        setPadding(dp(11),dp(9),dp(11),dp(9))
                        background=shape(Color.WHITE,13,border)
                        val ico=ImageView(this@MainActivity)
                        addView(ico,LinearLayout.LayoutParams(dp(41),dp(41)).apply{marginEnd=dp(11)})
                        val title=TextView(this@MainActivity).apply{
                            textSize=14.5f;setTextColor(navy)
                            maxLines=2;setTypeface(null,Typeface.BOLD);gravity=Gravity.RIGHT
                        }
                        addView(title,LinearLayout.LayoutParams(0,-2,1f))
                        val action=TextView(this@MainActivity).apply{
                            textSize=13f;gravity=Gravity.CENTER;setTypeface(null,Typeface.BOLD)
                        }
                        addView(action,LinearLayout.LayoutParams(dp(75),dp(38)).apply{marginStart=dp(9)})
                    }
                    (row.getChildAt(1) as TextView).text=data.first
                    val image=row.getChildAt(0) as ImageView
                    val cached=iconCache.get(data.second)
                    val drawable=cached ?: try{packageManager.getApplicationIcon(data.second).also{iconCache.put(data.second,it)}}
                        catch(_:Exception){getDrawable(R.drawable.ic_launcher)}
                    image.setImageDrawable(drawable)
                    val action=row.getChildAt(2) as TextView
                    val picked=data.second in selected
                    action.text=if(picked)"إلغاء" else if(allowOnly)"إضافة" else "قفل"
                    action.setTextColor(if(picked)Color.rgb(157,56,73) else teal)
                    action.background=shape(if(picked)Color.rgb(255,237,240) else lightTeal,11)
                    return row
                }
            }
            listView.adapter=adapter
            listView.setOnItemClickListener{_,_,position,_->
                val pkg=filtered[position].second
                val next=selected.toMutableSet()
                if(pkg in next)next.remove(pkg) else next.add(pkg)
                prefs.edit().putStringSet(if(allowOnly)"allow_packages" else "block_packages",next).apply()
                counter.text="المحدد حالياً: "+next.size
                adapter.notifyDataSetChanged()
                GuardService.instance?.refresh()
            }
            search.addTextChangedListener(object:TextWatcher {
                override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){}
                override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){
                    val q=s?.toString()?.trim()?.lowercase().orEmpty()
                    filtered.clear();filtered.addAll(if(q.isEmpty())items else items.filter{it.first.lowercase().contains(q)})
                    adapter.notifyDataSetChanged()
                }
                override fun afterTextChanged(e:Editable?){}
            })
            holder.addView(listView,LinearLayout.LayoutParams(-1,dp(460)))
        }
        val cached=cachedApps
        if(cached!=null)show(cached)
        else loading.execute{
            val items=apps()
            cachedApps=items
            runOnUiThread{show(items)}
        }
        label(panel,"للسماح أو القفل اضغط على سطر التطبيق. إذا تريد تشيله من القائمة اضغط عليه مرة ثانية.",13f,false,muted,12,0)
    }

    private fun renderSecurity() {
        label(panel,"الحماية والإعدادات",23f,true,navy,0,8)
        label(panel,"كل الموافقات بيدك، والتطبيق يحوّلك للمكان الصحيح.",14f,false,muted,0,17)
        val permissions=padBox(panel)
        label(permissions,"الأذونات المطلوبة",19f,true,navy,0,9)
        label(permissions,if(serviceEnabled())"✓ مراقبة التطبيقات: مفعّلة" else "✕ مراقبة التطبيقات: غير مفعّلة",
            15f,true,if(serviceEnabled())teal else Color.rgb(187,94,74),0,8)
        label(permissions,"نستخدم فقط اسم التطبيق المفتوح حتى نعّرف إذا مقفول، بدون قراءة الرسائل أو كلمات السر.",13f,false,muted,0,10)
        topButton(permissions,if(serviceEnabled())"عرض إعدادات الإذن" else "اطلب إذن مراقبة التطبيقات",true){requestAccessibility()}
        topButton(permissions,"السماح بالتشغيل بالخلفية",false){
            goToSettings(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        }
        topButton(permissions,"معلومات التطبيق وأذونات النظام",false){
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:"+packageName)))
        }
        label(panel,"رمز الحماية والتحقق",20f,true,navy,14,9)
        val codes=padBox(panel)
        inlineRow(codes,"تغيير رمز المشرف","6 إلى 12 رقم، محفوظ على الجهاز","⌑"){
            passDialog("أدخل الرمز الحالي"){p->verifyPinAsync(p){createPin()}}
        }
        inlineRow(codes,if(prefs.getBoolean("bio_enabled",false))"إيقاف البصمة والوجه" else
            "تشغيل البصمة أو الوجه","يعتمد على تحقق أندرويد الحقيقي","◈"){
            if(prefs.getBoolean("bio_enabled",false)){
                prefs.edit().putBoolean("bio_enabled",false).apply();render()
            }else if(biometricAvailable()){
                AlertDialog.Builder(this).setTitle("تفعيل تحقق الجهاز")
                    .setMessage("عند تفعيله، يستخدم القفل الشامل نافذة تحقق أندرويد الأصلية فقط. البصمة والوجه يعتمدان على دعم جهازك وإعداداته.")
                    .setNegativeButton("إلغاء",null).setPositiveButton("تفعيل"){_,_->
                        prefs.edit().putBoolean("bio_enabled",true).apply();render()
                    }.show()
            }else toast("ماكو بصمة أو وجه متاح عبر تحقق أندرويد على هذا الجهاز")
        }
        inlineRow(codes,"استعادة الرمز","رمز احتياطي محفوظ عندك، بدون حسابات خارجية","↺"){recoveryDialog()}
        label(panel,"المساعدة والتواصل",20f,true,navy,15,10)
        val help=padBox(panel)
        inlineRow(help,"دليل سريع","شلون تختار البرامج وتشغل الحماية؟","؟"){
            AlertDialog.Builder(this).setTitle("دليل القفل الشامل")
                .setMessage("١. افتح صفحة التطبيقات.\n٢. اختَر «اسمح لهذني فقط» أو «اقفل هذني فقط».\n٣. اضغط إضافة أو قفل مقابل كل تطبيق.\n٤. من صفحة الحماية امنح إذن إمكانية الوصول بموافقتك.\n٥. ارجع للرئيسية واضغط «تشغيل القفل الآن».\n\nإذا ما اشتغل القفل على POCO، اسمح للتطبيق بالتشغيل بالخلفية وبدون تقييد البطارية.\n\nما نقدر نمنع الحذف أو ضبط المصنع بشكل مضمون بدون إدارة الجهاز.")
                .setPositiveButton("تمام",null).show()
        }
        label(help,"المطور: مؤمل سعد",17f,true,navy,4,11)
        inlineRow(help,"تيليجرام","t.me/HEX_H","↗"){openSite("https://t.me/HEX_H")}
        inlineRow(help,"إنستغرام","5fk5__","↗"){openSite("https://www.instagram.com/5fk5__?rpxt=OXk5eHlhcnpocG50")}
        inlineRow(help,"فيسبوك","صفحة المطور","↗"){openSite("https://www.facebook.com/share/14nSSqTnygp/")}
        inlineRow(help,"إكس (تويتر)","M_A_L0","↗"){openSite("https://x.com/M_A_L0")}
        topButton(panel,"قفل لوحة التحكم بالرمز",false){adminOpen=false;section=0;render()}
        label(panel,"لا يوجد تسجيل حساب أو خادم لاستعادة الرمز حالياً. لا يمكن ضمان منع إيقاف الخدمة أو حذف التطبيق أو تجاوز كل واجهات النظام.",12f,false,muted,14)
    }
    private fun openSite(url:String){
        try{startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))}
        catch(_:Exception){toast("ماكو تطبيق يفتح الرابط")}
    }

    private fun apps():List<Pair<String,String>> {
        val intent=Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(intent,PackageManager.MATCH_ALL)
            .filter { it.activityInfo.packageName!=packageName }
            .map { it.loadLabel(packageManager).toString() to it.activityInfo.packageName }
            .distinctBy { it.second }.sortedBy { it.first.lowercase() }
    }
    private fun activate(){toggleProtection()}

}
