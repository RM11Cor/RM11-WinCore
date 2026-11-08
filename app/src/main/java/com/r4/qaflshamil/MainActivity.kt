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
    private fun text(s:String,large:Boolean=false) {
        val v=TextView(this).apply {
            text=s; textSize=if(large) 24f else 16f
            setTextColor(Color.rgb(23,48,72)); setPadding(8,14,8,14)
            gravity=Gravity.RIGHT
        }
        panel.addView(v)
    }
    private fun button(s:String,action:()->Unit) {
        val v=Button(this).apply {
            text=s; textSize=16f; isAllCaps=false
            setOnClickListener { action() }
        }
        panel.addView(v,LinearLayout.LayoutParams(-1,-2).apply { topMargin=10 })
    }
    private fun render() {
        panel=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(25,24,25,42)
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(Color.rgb(246,249,253))
        }
        setContentView(ScrollView(this).apply { addView(panel) })
        text("🔒 القفل الشامل",true)
        text("الواجهة عربية — تطبيق واحد أو عدة تطبيقات")
        if(!pinSet()) {
            text("أنشئ رمزاً سرياً أولاً. احفظه بمكان آمن.")
            button("إنشاء رمز الحماية") { createPin() }
            return
        }
        if(active && !adminOpen) {
            text("التطبيقات المسموحة",true)
            val names=apps().associateBy { it.second }
            selected.sorted().forEach { pkg->
                button("فتح "+(names[pkg]?.first ?: pkg)) { launch(pkg) }
            }
            button("⚙️ إعدادات المشرف (بالرمز)") { unlockAdmin() }
            return
        }
        if(!adminOpen) {
            text("لوحة الإدارة محمية بالرمز")
            text(if(owner) "✓ إدارة الجهاز مفعلة" else "إدارة الجهاز غير مفعّلة — لا يوجد قفل قوي بعد")
            button("دخول إعدادات المشرف") { unlockAdmin() }
            return
        }
        text("إعدادات المشرف",true)
        text(if(owner) "✓ وضع إدارة الجهاز متاح" else "⚠ لا يمكن منع الحذف أو استخدام القفل الكامل قبل تفعيل Device Owner")
        text(if(active) "الحالة: القفل يعمل" else "الحالة: متوقف")
        if(!active) {
            text("الوضع: "+if(single) "تطبيق واحد" else "عدة تطبيقات")
            button(if(single) "تغيير إلى عدة تطبيقات" else "تغيير إلى تطبيق واحد") {
                val wasSingle=single
                prefs.edit().putBoolean("single",!wasSingle).commit()
                if(!wasSingle && selected.size>1) prefs.edit().putStringSet("allowed",setOf(selected.first())).commit()
                render()
            }
            button("تحديد التطبيقات المسموحة ("+selected.size+")") { pickApps() }
            button("تغيير رمز المشرف") { passDialog("تحقق من الرمز الحالي") {
                if(checkPin(it)) createPin()
            } }
            button("تفعيل القفل الشامل") { activate() }
            if(owner) button("فك إدارة الجهاز — اختبار فقط") {
                passDialog("رمز المشرف لفك الإدارة") { if(checkPin(it)) releaseOwner() }
            }
            if(!owner) text("التثبيت العادي لا يعطي صلاحية Device Owner. لا تفعّلها على جهازك الأساسي قبل تجربة التطبيق على جهاز احتياطي.")
        } else {
            text("المسموح: "+selected.size+" تطبيق")
            button("إيقاف القفل بعد التحقق") {
                passDialog("الرمز لإيقاف القفل") { if(checkPin(it)) deactivate() }
            }
        }
        button("إغلاق إعدادات المشرف") { adminOpen=false; render() }
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