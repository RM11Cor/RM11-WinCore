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
import android.graphics.drawable.GradientDrawable
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
                    .setPositiveButton("حفظته"){_,_->requestRequiredPermissions()}.setCancelable(false).show()
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
    private fun usageGranted():Boolean=try {
        val ops=getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
        ops.checkOpNoThrow(android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,android.os.Process.myUid(),packageName)==android.app.AppOpsManager.MODE_ALLOWED
    }catch(_:Exception){false}
    private fun overlayGranted():Boolean=Settings.canDrawOverlays(this)
    private fun serviceEnabled()=usageGranted() && overlayGranted()
    private fun goToSettings(action:String){
        try{startActivity(Intent(action))}
        catch(_:Exception){startActivity(Intent(Settings.ACTION_SETTINGS))}
    }
    private fun requestRequiredPermissions(){
        if(!usageGranted()){
            AlertDialog.Builder(this).setTitle("السماح بمراقبة استخدام التطبيقات")
                .setMessage("حتى يعرف القفل الشامل اسم التطبيق المفتوح ويطبق قائمتك، يحتاج إذن «الوصول إلى بيانات الاستخدام».\n\nيُستعمل هذا الإذن محلياً فقط لاكتشاف التطبيق الظاهر، ولا نقرأ الرسائل أو كلمات المرور ولا نرسل سجل الاستخدام لأي جهة. يمكنك رفضه أو إلغاؤه من إعدادات الجهاز.")
                .setNegativeButton("مو هسه",null)
                .setPositiveButton("أوافق وأفتح الإعدادات"){_,_->
                    goToSettings(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                }.show()
            return
        }
        if(!overlayGranted()){
            AlertDialog.Builder(this).setTitle("السماح بعرض شاشة القفل")
                .setMessage("حتى تظهر شاشة الرمز فوق التطبيق المقفول، يحتاج القفل الشامل إذن «الظهور فوق التطبيقات الأخرى».\n\nلن يظهر فوق التطبيقات إلا عند تفعيل القفل وفتح تطبيق مقفول. بإمكانك إيقافه بأي وقت من إعدادات الجهاز.")
                .setNegativeButton("مو هسه",null)
                .setPositiveButton("أوافق وأفتح الإعدادات"){_,_->
                    try{
                        startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,Uri.parse("package:"+packageName)))
                    }catch(_:Exception){goToSettings(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)}
                }.show()
            return
        }
        toast("كل الأذونات اللازمة مفعّلة")
    }
    private fun changeMode(toAllow:Boolean){
        if(allowOnly==toAllow)return
        prefs.edit().putInt("mode",if(toAllow)0 else 1).apply()
        GuardService.instance?.refresh()
        render()
    }
    private fun toggleProtection(){
        if(active) {
            passDialog("رمز المشرف لإيقاف القفل"){code->
                verifyPinAsync(code){
                    prefs.edit().putBoolean("active",false).apply()
                    stopService(Intent(this,GuardService::class.java))
                    GuardService.instance?.hideOverlay()
                    toast("تم إيقاف القفل")
                    render()
                }
            }
        } else {
            if(selected.isEmpty()) {
                AlertDialog.Builder(this).setTitle("قائمة التطبيقات فارغة")
                    .setMessage(if(allowOnly)"اختَر تطبيقاً واحداً على الأقل ضمن قائمة السماح. بعض أدوات النظام الأساسية تبقى متاحة للسلامة." else "اختَر التطبيقات اللي تريد تقفلها أولاً.")
                    .setPositiveButton("اختيار التطبيقات"){_,_->section=1;render()}
                    .setNegativeButton("إلغاء",null).show()
                return
            }
            if(!serviceEnabled()){
                AlertDialog.Builder(this).setTitle("باقي موافقات النظام")
                    .setMessage("حتى يشتغل القفل، نحتاج موافقتك على الوصول لبيانات الاستخدام والظهور فوق التطبيقات. بدونهن ما نكدر نفرض القفل.")
                    .setNegativeButton("رجوع",null)
                    .setPositiveButton("افتح إعدادات الأذونات"){_,_->requestRequiredPermissions()}
                    .show()
                return
            }
            prefs.edit().putBoolean("active",true).commit()
            try {
                val guard=Intent(this,GuardService::class.java)
                if(Build.VERSION.SDK_INT>=26)startForegroundService(guard)
                else startService(guard)
                toast("تم طلب تشغيل القفل. تظهر إشعارة مراقبة مستمرة أثناء عمله.")
            }catch(e:Exception){
                prefs.edit().putBoolean("active",false).commit()
                toast("تعذّر بدء الحماية: "+e.javaClass.simpleName)
            }
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

    private fun inlineRow(host:LinearLayout,title:String,detail:String,mark:String,click:()->Unit) {
        val line=LinearLayout(this).apply {
            orientation=LinearLayout.HORIZONTAL
            gravity=Gravity.CENTER_VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(8),dp(15),dp(8),dp(15))
            isClickable=true;isFocusable=true
            setOnClickListener{click()}
        }
        val symbol=TextView(this).apply {
            text=mark;textSize=21f;gravity=Gravity.CENTER
            setTextColor(teal);background=shape(lightTeal,14)
        }
        line.addView(symbol,LinearLayout.LayoutParams(dp(46),dp(46)).apply{marginEnd=dp(12)})
        val mid=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        label(mid,title,15.5f,true,navy)
        label(mid,detail,13f,false,muted,3,0)
        line.addView(mid,LinearLayout.LayoutParams(0,-2,1f))
        val arrow=TextView(this).apply{text="‹";textSize=25f;setTextColor(muted)}
        line.addView(arrow)
        host.addView(line)
        host.addView(View(this).apply{setBackgroundColor(border)},LinearLayout.LayoutParams(-1,dp(1)))
    }
    private fun titleText(sectionId:Int)=when(sectionId) {
        0->"الرئيسية"
        1->"التطبيقات"
        2->"الحماية"
        3->"الإعدادات"
        4->"المزيد"
        5->"مركز المساعدة"
        else->"عن المطوّر"
    }
    private fun header(root:LinearLayout,subtitle:String) {
        val bar=LinearLayout(this).apply {
            orientation=LinearLayout.HORIZONTAL
            gravity=Gravity.CENTER_VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(19),dp(17),dp(19),dp(17))
            setBackgroundColor(Color.WHITE)
        }
        val logo=ImageView(this).apply{
            setImageResource(R.drawable.ic_launcher)
            scaleType=ImageView.ScaleType.FIT_CENTER
            background=shape(lightTeal,15)
            setPadding(dp(5),dp(5),dp(5),dp(5))
        }
        bar.addView(logo,LinearLayout.LayoutParams(dp(50),dp(50)).apply{marginEnd=dp(12)})
        val words=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        label(words,"القفل الشامل",21f,true,deep)
        label(words,subtitle,12.5f,false,muted,3)
        bar.addView(words,LinearLayout.LayoutParams(0,-2,1f))
        val more=ImageView(this).apply{
            setImageResource(R.drawable.nav_more)
            setColorFilter(navy)
            setPadding(dp(12),dp(12),dp(12),dp(12))
            isClickable=true
            contentDescription="القائمة"
            setOnClickListener{if(adminOpen){section=4;render()}else unlockAdmin()}
        }
        bar.addView(more,LinearLayout.LayoutParams(dp(46),dp(46)))
        root.addView(bar)
        root.addView(View(this).apply{setBackgroundColor(border)},LinearLayout.LayoutParams(-1,dp(1)))
    }
    private fun nav(root:LinearLayout) {
        val labels=arrayOf("الرئيسية","التطبيقات","الحماية","الإعدادات","المزيد")
        val icons=intArrayOf(R.drawable.nav_home,R.drawable.nav_apps,R.drawable.nav_shield,
            R.drawable.nav_settings,R.drawable.nav_more)
        val selectedTab=if(section>=5)4 else section
        val row=LinearLayout(this).apply{
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(Color.WHITE)
            setPadding(dp(5),dp(9),dp(5),dp(6))
        }
        for(index in labels.indices) {
            val selected=index==selectedTab
            val item=LinearLayout(this).apply{
                orientation=LinearLayout.VERTICAL;gravity=Gravity.CENTER
                setPadding(dp(2),dp(3),dp(2),dp(3))
                isClickable=true
                background=shape(if(selected)lightTeal else Color.WHITE,14)
                setOnClickListener{section=index;render()}
                contentDescription=labels[index]
            }
            val glyph=ImageView(this).apply{
                setImageResource(icons[index])
                setColorFilter(if(selected)teal else muted)
                scaleType=ImageView.ScaleType.FIT_CENTER
            }
            item.addView(glyph,LinearLayout.LayoutParams(dp(23),dp(23)).apply{bottomMargin=dp(6)})
            val text=TextView(this).apply{
                this.text=labels[index];textSize=11.5f
                gravity=Gravity.CENTER
                setTextColor(if(selected)teal else muted)
                if(selected)typeface=Typeface.DEFAULT_BOLD
            }
            item.addView(text)
            row.addView(item,LinearLayout.LayoutParams(0,dp(66),1f))
        }
        root.addView(View(this).apply{setBackgroundColor(border)},LinearLayout.LayoutParams(-1,dp(1)))
        root.addView(row)
    }
    private fun sectionTitle(title:String,subtitle:String) {
        label(panel,title,24f,true,deep,0,6)
        label(panel,subtitle,14f,false,muted,0,18)
    }
    private fun statusChip(text:String,positive:Boolean):TextView {
        return TextView(this).apply{
            this.text=text;textSize=12f
            setTypeface(null,Typeface.BOLD)
            setTextColor(if(positive)Color.rgb(25,118,94) else Color.rgb(170,110,34))
            setPadding(dp(12),dp(7),dp(12),dp(7))
            background=shape(if(positive)Color.rgb(228,247,238) else Color.rgb(255,246,224),22)
        }
    }
    private fun horizontalModePills(host:LinearLayout) {
        val row=LinearLayout(this).apply{
            orientation=LinearLayout.HORIZONTAL;layoutDirection=View.LAYOUT_DIRECTION_RTL
        }
        for(i in 0..1) {
            val chooseAllow=i==0
            val chosen=allowOnly==chooseAllow
            val mode=TextView(this).apply{
                text=if(chooseAllow)"السماح المحدد" else "القفل المحدد"
                textSize=14.5f;gravity=Gravity.CENTER
                typeface=if(chosen)Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                setTextColor(if(chosen)Color.WHITE else navy)
                background=if(chosen)
                    GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,
                        intArrayOf(Color.rgb(39,154,236),Color.rgb(117,80,230))).apply{
                            cornerRadius=dp(13).toFloat()
                        } else shape(lightTeal,13)
                isClickable=true
                setOnClickListener{changeMode(chooseAllow)}
            }
            row.addView(mode,LinearLayout.LayoutParams(0,dp(48),1f).apply{
                marginEnd=dp(if(i==0)5 else 0);marginStart=dp(if(i==1)5 else 0)
            })
        }
        host.addView(row)
    }
    private fun socialRow(host:LinearLayout,title:String,handle:String,iconRes:Int,url:String,color:Int){
        val line=LinearLayout(this).apply{
            orientation=LinearLayout.HORIZONTAL
            gravity=Gravity.CENTER_VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(8),dp(16),dp(8),dp(16))
            isClickable=true
            contentDescription="فتح حساب "+title
            setOnClickListener{openSite(url)}
        }
        val emblem=ImageView(this).apply{
            setImageResource(iconRes)
            scaleType=ImageView.ScaleType.FIT_CENTER
            background=shape(Color.rgb(248,250,253),13)
            setPadding(dp(12),dp(12),dp(12),dp(12))
        }
        line.addView(emblem,LinearLayout.LayoutParams(dp(50),dp(50)).apply{marginEnd=dp(12)})
        val words=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        label(words,title,16f,true,navy)
        label(words,handle,13f,false,muted,4)
        line.addView(words,LinearLayout.LayoutParams(0,-2,1f))
        val arrow=TextView(this).apply{text="↗";textSize=25f;setTextColor(color)}
        line.addView(arrow)
        host.addView(line)
        host.addView(View(this).apply{setBackgroundColor(border)},LinearLayout.LayoutParams(-1,dp(1)))
    }
    private fun render() {
        val root=LinearLayout(this).apply{
            orientation=LinearLayout.VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(bg)
            fitsSystemWindows=true
        }
        setContentView(root)
        val subtitle=when{
            !pinSet()->"البدء وإعداد رمز الأمان"
            !adminOpen->"الدخول الآمن"
            else->titleText(section)
        }
        header(root,subtitle)
        val scroll=ScrollView(this).apply{
            isFillViewport=true
            isVerticalScrollBarEnabled=false
            clipToPadding=false
        }
        panel=LinearLayout(this).apply{
            orientation=LinearLayout.VERTICAL
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(18),dp(19),dp(18),dp(30))
        }
        scroll.addView(panel)
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        when {
            !pinSet()->renderWelcome()
            !adminOpen->renderGate()
            else -> {
                when(section) {
                    0->renderHome()
                    1->renderPicker()
                    2->renderSecurity()
                    3->renderSettings()
                    4->renderMore()
                    5->renderHelp()
                    else->renderDeveloper()
                }
                nav(root)
            }
        }
    }

    private fun renderWelcome() {
        val card=padBox(panel,deep,false)
        label(card,"الخصوصية تحت سيطرتك",27f,true,Color.WHITE,6,14)
        label(card,"أنشئ رمز حماية محلياً، واختر التطبيقات التي تريد السماح بها أو قفلها. كل قرار بيدك.",15f,false,Color.rgb(214,229,252),0,14)
        val start=padBox(panel)
        label(start,"مرحباً بك في القفل الشامل",20f,true,deep,3,11)
        label(start,"١. إنشاء رمز الحماية",15.5f,true,navy,0,5)
        label(start,"يُخزَّن الرمز بشكل آمن على جهازك، مع رمز استعادة احتياطي.",13.5f,false,muted,0,16)
        label(start,"٢. تحديد طريقة القفل",15.5f,true,navy,0,5)
        label(start,"السماح بتطبيقات محددة، أو قفل التطبيقات التي تختارها فقط.",13.5f,false,muted,0,16)
        label(start,"٣. منح الأذونات المطلوبة",15.5f,true,navy,0,5)
        label(start,"ستظهر نافذة توضيح لكل إذن، ولن يُمنح تلقائياً.",13.5f,false,muted,0,12)
        topButton(start,"إنشاء رمز الحماية"){createPin()}
        label(panel,"يتطلب قفل التطبيقات مراقبة استخدامها وعرض نافذة الرمز. يمكنك رفض هذه الأذونات والاطلاع على الخصوصية قبل تفعيل القفل.",13f,false,muted,14)
    }
    private fun renderGate() {
        val hero=padBox(panel,deep,false)
        label(hero,if(active)"● الحماية مُفعّلة" else "○ الحماية متوقفة",15f,true,
            if(active)Color.rgb(143,242,207) else Color.rgb(255,221,162),2,14)
        label(hero,"مرحباً بعودتك",25f,true,Color.WHITE,0,8)
        label(hero,"ادخل إلى لوحة التحكم باستخدام رمز الحماية أو البصمة المفعّلة على جهازك.",14.5f,false,Color.rgb(205,225,250),0,13)
        topButton(hero,"فتح لوحة التحكم"){unlockAdmin()}
        val state=padBox(panel)
        label(state,"حالة الصلاحيات",18f,true,navy,2,11)
        val ok=serviceEnabled()
        state.addView(statusChip(if(ok)"جميع الأذونات الأساسية مُفعّلة" else "توجد أذونات لم يتم منحها",ok))
        if(!ok)topButton(state,"عرض الأذونات اللازمة",false){requestRequiredPermissions()}
        inlineRow(state,"استعادة الوصول","استخدام رمز الاستعادة الاحتياطي","↺"){recoveryDialog()}
    }
    private fun renderHome() {
        val hero=padBox(panel,deep,false)
        label(hero,"لوحة التحكم",14f,true,Color.rgb(160,206,255),0,7)
        label(hero,if(active)"الحماية قيد التشغيل" else "حماية على طريقتك",25f,true,Color.WHITE,0,9)
        label(hero,if(active)"يمكنك إيقاف المراقبة بعد تأكيد رمز الحماية." else
            "اختر طريقة القفل وحدد التطبيقات، ثم امنح الأذونات المطلوبة لتبدأ.",14f,false,Color.rgb(210,226,246),0,13)
        hero.addView(statusChip(if(serviceEnabled())"الأذونات مكتملة" else "الأذونات غير مكتملة",serviceEnabled()))
        label(panel,"طريقة قفل التطبيقات",21f,true,navy,14,10)
        val method=padBox(panel)
        horizontalModePills(method)
        label(method,if(allowOnly)"السماح بالتطبيقات المحددة" else "قفل التطبيقات المحددة",
            17.5f,true,navy,15,7)
        label(method,if(allowOnly)
            "ستظهر شاشة الحماية عند فتح أي تطبيق غير موجود في قائمة السماح، باستثناء أدوات النظام الضرورية."
            else "ستظهر شاشة الحماية على التطبيقات التي تختار قفلها فقط.",
            14f,false,muted,0,4)
        label(panel,"ملخص القوائم",19f,true,navy,14,11)
        val stats=padBox(panel)
        val r=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;layoutDirection=View.LAYOUT_DIRECTION_RTL}
        for(pair in listOf("المسموح بها" to "allow_packages","المقفلة" to "block_packages")){
            val item=LinearLayout(this).apply{
                orientation=LinearLayout.VERTICAL;gravity=Gravity.CENTER
                background=shape(bg,15)
                setPadding(dp(7),dp(15),dp(7),dp(15))
            }
            val count=prefs.getStringSet(pair.second,emptySet()).orEmpty().size
            label(item,count.toString(),27f,true,teal).gravity=Gravity.CENTER
            label(item,pair.first,13f,false,muted,4).gravity=Gravity.CENTER
            r.addView(item,LinearLayout.LayoutParams(0,-2,1f).apply{marginEnd=dp(5)})
        }
        stats.addView(r)
        topButton(stats,"إدارة قوائم التطبيقات",false){section=1;render()}
        topButton(panel,if(active)"إيقاف الحماية" else "تشغيل الحماية"){toggleProtection()}
        if(!serviceEnabled())topButton(panel,"مراجعة الأذونات",false){section=2;render()}
        label(panel,"تنبيه توضيحي: لا يمنع هذا التطبيق حذف نفسه أو إيقاف الأذونات. يعتمد القفل على قيود نظام التشغيل وموافقات المستخدم.",12.5f,false,muted,16)
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
        label(permissions,if(serviceEnabled())"✓ الأذونات الأساسية مفعّلة" else "✕ بعض الأذونات الأساسية مو مفعّلة",
            15f,true,if(serviceEnabled())teal else Color.rgb(187,94,74),0,8)
        label(permissions,"بيانات الاستخدام: "+if(usageGranted())"مسموح" else "تحتاج موافقة",14f,false,if(usageGranted())teal else muted,0,7)
        label(permissions,"الظهور فوق التطبيقات: "+if(overlayGranted())"مسموح" else "تحتاج موافقة",14f,false,if(overlayGranted())teal else muted,0,9)
        label(permissions,"نستخدم محلياً اسم التطبيق المفتوح فقط، ونظهر شاشة الرمز وقت الحاجة. لا نطلب أذونات الاستخدام والظهور فوق التطبيقات ولا نقرأ الرسائل أو كلمات المرور.",13f,false,muted,0,10)
        topButton(permissions,if(serviceEnabled())"عرض إعدادات الإذن" else "اطلب إذن مراقبة التطبيقات",true){requestRequiredPermissions()}
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
                .setMessage("١. افتح صفحة التطبيقات.\n٢. اختَر «اسمح لهذني فقط» أو «اقفل هذني فقط».\n٣. اضغط إضافة أو قفل مقابل كل تطبيق.\n٤. من صفحة الحماية امنح أذونات الاستخدام والظهور فوق التطبيقات بموافقتك.\n٥. ارجع للرئيسية واضغط «تشغيل القفل الآن».\n\nإذا ما اشتغل القفل على POCO، اسمح للتطبيق بالتشغيل بالخلفية وبدون تقييد البطارية. إذا لم تظهر صلاحية فوق التطبيقات، افتح «الوصول الخاص للتطبيقات» من إعدادات الهاتف.\n\nما نقدر نمنع الحذف أو ضبط المصنع بشكل مضمون بدون إدارة الجهاز.")
                .setPositiveButton("تمام",null).show()
        }
        label(help,"المطور: مؤمل سعد",17f,true,navy,4,11)
        inlineRow(help,"تيليجرام","t.me/HEX_H","↗"){openSite("https://t.me/HEX_H")}
        inlineRow(help,"إنستغرام","5fk5__","↗"){openSite("https://www.instagram.com/5fk5__?rpxt=OXk5eHlhcnpocG50")}
        inlineRow(help,"فيسبوك","صفحة المطور","↗"){openSite("https://www.facebook.com/share/14nSSqTnygp/")}
        inlineRow(help,"إكس (تويتر)","M_A_L0","↗"){openSite("https://x.com/M_A_L0")}
        topButton(panel,"قفل لوحة التحكم بالرمز",false){adminOpen=false;section=0;render()}
        label(panel,"لا يوجد تسجيل حساب أو خادم لاستعادة الرمز حالياً. لا يمكن ضمان منع إيقاف خدمة المراقبة أو حذف التطبيق أو تجاوز كل واجهات النظام.",12f,false,muted,14)
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

}
