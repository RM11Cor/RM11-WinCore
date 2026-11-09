package com.r4.qaflshamil

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Executors
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Minimal, opt-in accessibility blocker. Only uses event.packageName.
 * It never reads node trees, text, keystrokes, or user messages.
 * An accessibility service can be disabled by the device owner;
 * this is not a full-device-management or anti-uninstall solution.
 */
class GuardService: AccessibilityService() {
    companion object { @Volatile var instance: GuardService?=null; private set }
    private val settings by lazy { getSharedPreferences("arabic_lock_settings",Context.MODE_PRIVATE) }
    private val wm by lazy { getSystemService(WINDOW_SERVICE) as WindowManager }
    private val io=Executors.newSingleThreadExecutor()
    private val ui=Handler(Looper.getMainLooper())
    private var overlay: View?=null
    private var overlayFor: String?=null
    private var lastForeground:String?=null
    private var granted:String?=null
    private var digits=""
    private var pinView:TextView?=null
    private var busy=false
    private var loading=false
    private val ink=Color.rgb(235,243,255)
    private val dim=Color.rgb(153,178,204)
    private val dark=Color.rgb(8,14,35)
    private fun dp(v:Int)= (v*resources.displayMetrics.density+0.5f).toInt()
    private fun bg(color:Int,r:Int=18)=GradientDrawable().apply {
        setColor(color); cornerRadius=dp(r).toFloat()
    }
    override fun onServiceConnected() {
        super.onServiceConnected()
        instance=this
        ui.post { Toast.makeText(this,"تم تشغيل مراقبة القفل الشامل",Toast.LENGTH_SHORT).show() }
    }
    override fun onDestroy() {
        hideOverlay()
        instance=null
        io.shutdown()
        super.onDestroy()
    }
    override fun onInterrupt() { hideOverlay() }
    fun refresh() {
        if(!settings.getBoolean("active",false)) { hideOverlay(); return }
        lastForeground?.let { check(it) }
    }
    fun hideOverlay() {
        try { overlay?.let { wm.removeViewImmediate(it) } } catch(_:Exception) {}
        overlay=null;overlayFor=null;digits="";pinView=null;busy=false
    }
    fun grantUnlock(pkg:String) {
        if(pkg.isBlank())return
        granted=pkg
        hideOverlay()
    }
    override fun onAccessibilityEvent(event:AccessibilityEvent?) {
        if(event==null || (event.eventType!=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            event.eventType!=AccessibilityEvent.TYPE_WINDOWS_CHANGED)) return
        val pkg=event.packageName?.toString() ?: return
        if(pkg==packageName) { hideOverlay(); return }
        // System UI and input components are not normal launchable apps.
        // These exclusions are necessary for keyboard, emergency and keyguard operation.
        if(pkg=="android"||pkg=="com.android.systemui"||
            pkg=="com.google.android.permissioncontroller"||pkg=="com.android.permissioncontroller"||
            pkg=="com.google.android.inputmethod.latin"||pkg=="com.android.inputmethod.latin"||
            pkg=="com.miui.home"||pkg=="com.android.launcher3"||
            pkg=="com.google.android.apps.nexuslauncher") return
        if(pkg!=lastForeground) {
            lastForeground=pkg
            if(pkg!=granted)granted=null
        }
        if(!settings.getBoolean("active",false)) {hideOverlay();return}
        check(pkg)
    }
    private fun check(pkg:String) {
        val allowOnly=settings.getInt("mode",0)==0
        val key=if(allowOnly)"allow_packages" else "block_packages"
        val chosen=settings.getStringSet(key,emptySet()).orEmpty()
        val blocked=if(allowOnly)pkg !in chosen else pkg in chosen
        if(!blocked || granted==pkg) {hideOverlay();return}
        if(overlayFor==pkg && overlay!=null)return
        if(loading)return
        loading=true
        ui.post {
            loading=false
            if(!settings.getBoolean("active",false) || lastForeground!=pkg)return@post
            showLock(pkg)
        }
    }
    private fun button(s:String, host:LinearLayout,fn:()->Unit) {
        val v=TextView(this).apply {
            text=s; textSize=17f;gravity=Gravity.CENTER
            setTextColor(ink);typeface=Typeface.DEFAULT_BOLD
            background=bg(Color.rgb(28,44,77),14)
            setOnClickListener{fn()}
        }
        host.addView(v,LinearLayout.LayoutParams(0,dp(56),1f).apply {
            leftMargin=dp(5);rightMargin=dp(5);bottomMargin=dp(8)
        })
    }
    private fun showLock(pkg:String) {
        hideOverlay()
        val root=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;gravity=Gravity.CENTER
            layoutDirection=View.LAYOUT_DIRECTION_RTL
            setPadding(dp(24),dp(16),dp(24),dp(16))
            background=GradientDrawable(GradientDrawable.Orientation.TL_BR,
                intArrayOf(Color.rgb(8,14,35),Color.rgb(18,31,69))).apply {cornerRadius=0f}
        }
        fun line(s:String,size:Float,color:Int=ink,bold:Boolean=false):TextView {
            val v=TextView(this).apply {
                text=s;textSize=size;gravity=Gravity.CENTER;setTextColor(color)
                if(bold)typeface=Typeface.DEFAULT_BOLD
            }
            root.addView(v,LinearLayout.LayoutParams(-1,-2).apply{bottomMargin=dp(12)})
            return v
        }
        line("◆",48f,Color.rgb(80,221,235),true)
        line("هذا التطبيق مقفول",25f,ink,true)
        val appName=try{packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg,0)).toString()}
            catch(_:Exception){pkg}
        line(appName,18f,dim)
        line("أدخل رمزك حتى تفتحه هالمرة",14f,dim)
        pinView=line("○ ○ ○ ○ ○ ○",23f,Color.rgb(90,219,236))
        val numberGrid=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
        root.addView(numberGrid,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(9)})
        val numbers=listOf(listOf("١","٢","٣"),listOf("٤","٥","٦"),
            listOf("٧","٨","٩"),listOf("مسح","٠","⌫"))
        val vals=listOf(listOf("1","2","3"),listOf("4","5","6"),
            listOf("7","8","9"),listOf("clear","0","del"))
        for(i in numbers.indices) {
            val row=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL}
            for(j in numbers[i].indices) {
                val action=vals[i][j]
                button(numbers[i][j],row) {
                    when(action) {
                        "clear" -> digits=""
                        "del" -> if(digits.isNotEmpty())digits=digits.dropLast(1)
                        else -> if(digits.length<12)digits+=action
                    }
                    pinView?.text="● ".repeat(digits.length).ifBlank{"○ ○ ○ ○ ○ ○"}
                }
            }
            numberGrid.addView(row,LinearLayout.LayoutParams(-1,-2))
        }
        val confirm=TextView(this).apply {
            text="فتح التطبيق";textSize=17f
            setTextColor(Color.rgb(8,15,30));typeface=Typeface.DEFAULT_BOLD
            gravity=Gravity.CENTER;background=bg(Color.rgb(90,219,236))
            setOnClickListener { verify(pkg) }
        }
        root.addView(confirm,LinearLayout.LayoutParams(-1,dp(53)).apply {topMargin=dp(8)})
        val biom=TextView(this).apply {
            text="البصمة أو الوجه (إذا يدعم جهازك)"
            textSize=14f;setTextColor(Color.rgb(188,167,255))
            gravity=Gravity.CENTER;setPadding(0,dp(18),0,dp(12))
            setOnClickListener{
                if(!settings.getBoolean("bio_enabled",false)) {
                    Toast.makeText(this@GuardService,"فعّل البصمة من إعدادات القفل الشامل أولاً",Toast.LENGTH_LONG).show()
                } else {
                    try {
                        val intent=android.content.Intent(this@GuardService,UnlockActivity::class.java)
                            .putExtra("target_pkg",pkg).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                        hideOverlay()
                        startActivity(intent)
                    } catch(e:Exception) {
                        Toast.makeText(this@GuardService,"تعذّر فتح البصمة؛ استخدم الرمز",Toast.LENGTH_SHORT).show()
                        showLock(pkg)
                    }
                }
            }
        }
        root.addView(biom)
        val params=WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_FULLSCREEN,
            android.graphics.PixelFormat.OPAQUE
        )
        params.gravity=Gravity.CENTER
        try {
            wm.addView(root,params)
            overlay=root;overlayFor=pkg
        } catch(e:Exception) {
            overlay=null;overlayFor=null
        }
    }
    private fun verify(pkg:String) {
        if(busy || digits.length<6) {
            if(digits.length<6)Toast.makeText(this,"اكتب الرمز كاملاً",Toast.LENGTH_SHORT).show()
            return
        }
        busy=true
        val value=digits
        digits="";pinView?.text="جاري التحقق..."
        io.execute {
            val now=System.currentTimeMillis()
            val next=settings.getLong("retry_after",0L)
            val ok=if(now<next)false else try{
                val salt=Base64.getDecoder().decode(settings.getString("pin_salt","")!!)
                val expected=Base64.getDecoder().decode(settings.getString("pin_hash","")!!)
                val spec=PBEKeySpec(value.toCharArray(),salt,160_000,256)
                val result=try{SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded}
                    finally{spec.clearPassword()}
                MessageDigest.isEqual(expected,result)
            }catch(_:Exception){false}
            if(ok)settings.edit().putInt("failures",0).putLong("retry_after",0L).apply()
            else if(now>=next){
                val failures=settings.getInt("failures",0)+1
                val wait=if(failures>=5)(30_000L*(1L shl (failures-5).coerceAtMost(5))).coerceAtMost(900_000L) else 0L
                settings.edit().putInt("failures",failures).putLong("retry_after",now+wait).apply()
            }
            ui.post {
                busy=false
                if(ok){grantUnlock(pkg)}
                else {
                    pinView?.text=if(now<next)"انتظر قبل المحاولة" else "الرمز مو صحيح"
                    Toast.makeText(this,"لم يتم فتح التطبيق",Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}