package com.r4.qaflshamil

import android.app.Service
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.Process
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Opt-in app monitoring via UsageStatsManager. No Accessibility, SMS,
 * notification listener, full-screen intent, or Internet permission.
 *
 * Requires TWO explicit user grants: Usage access and Draw over other apps.
 * Never reads windows, user inputs, messages, or passwords of other apps.
 * Foreground service exposes a persistent system-managed notification.
 * This is best-effort app blocking, not device-management anti-tamper.
 */
class GuardService: Service() {
    companion object { @Volatile var instance: GuardService?=null; private set }
    private val settings by lazy { getSharedPreferences("arabic_lock_settings",Context.MODE_PRIVATE) }
    private val wm by lazy { getSystemService(WINDOW_SERVICE) as WindowManager }
    private val usage by lazy { getSystemService(USAGE_STATS_SERVICE) as UsageStatsManager }
    private val power by lazy { getSystemService(POWER_SERVICE) as PowerManager }
    private val io=Executors.newSingleThreadExecutor()
    private val checks=Executors.newSingleThreadExecutor()
    private val pending=AtomicBoolean(false)
    @Volatile private var lastEventQueryAt=System.currentTimeMillis()-8_000L
    private val ui=Handler(Looper.getMainLooper())
    private var overlay:View?=null
    private var overlayFor:String?=null
    private var lastForeground:String?=null
    private var granted:String?=null
    private var digits=""
    private var pinView:TextView?=null
    private var busy=false
    private val ink=Color.rgb(235,243,255)
    private val dim=Color.rgb(153,178,204)

    private val polling=object:Runnable {
        override fun run() {
            if(!settings.getBoolean("active",false)){stopSelf();return}
            if(MainActivity.foreground) {
                hideOverlay()
            } else if(!Settings.canDrawOverlays(this@GuardService) || !hasUsagePermission()){
                settings.edit().putBoolean("active",false)
                    .putString("last_guard_error","تم سحب إذن بيانات الاستخدام أو الظهور فوق التطبيقات. توقفت الحماية.").apply()
                hideOverlay()
                stopSelf()
                return
            } else if(!power.isInteractive) {
                hideOverlay()
            } else if(pending.compareAndSet(false,true)){
                checks.execute {
                    val pkg=try{latestForeground()}catch(_:Exception){null}
                    pending.set(false)
                    if(pkg!=null)ui.post{
                        if(!MainActivity.foreground && settings.getBoolean("active",false))checkForeground(pkg)
                    }
                }
            }
            ui.postDelayed(this,550L)
        }
    }
    private fun hasUsagePermission():Boolean {
        val ops=getSystemService(APP_OPS_SERVICE) as AppOpsManager
        return ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,Process.myUid(),packageName)==AppOpsManager.MODE_ALLOWED
    }
    private fun latestForeground():String? {
        val now=System.currentTimeMillis()
        val from=(lastEventQueryAt-1_200L).coerceAtLeast(now-60_000L)
        lastEventQueryAt=now
        val events=usage.queryEvents(from,now)
        val event=UsageEvents.Event()
        var pkg:String?=null
        var last=0L
        while(events.hasNextEvent()){
            events.getNextEvent(event)
            if(event.eventType==UsageEvents.Event.ACTIVITY_RESUMED && event.timeStamp>last) {
                pkg=event.packageName
                last=event.timeStamp
            }
        }
        return pkg
    }
    override fun onBind(intent:Intent?):IBinder?=null
    override fun onCreate() {
        super.onCreate()
        instance=this
    }
    override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
        if(!settings.getBoolean("active",false) || !Settings.canDrawOverlays(this) || !hasUsagePermission()){
            settings.edit().putBoolean("active",false)
                .putString("last_guard_error","لم تُمنح الأذونات المطلوبة أو تم إلغاؤها").apply()
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            val manager=getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            val channel="alq_local_guard"
            manager.createNotificationChannel(NotificationChannel(channel,"القفل الشامل • مراقبة التطبيقات",NotificationManager.IMPORTANCE_LOW).apply{
                description="قفل التطبيقات المحددة فقط عندما تكون الحماية مفعلة."
                setShowBadge(false)
            })
            val open=Intent(this,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            val pi=android.app.PendingIntent.getActivity(this,0,open,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE)
            val note=Notification.Builder(this,channel)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("القفل الشامل يعمل")
                .setContentText("انقر لإدارة الحماية أو إيقافها باستخدام الرمز.")
                .setContentIntent(pi)
                .setOngoing(true).build()
            if(Build.VERSION.SDK_INT>=34)startForeground(8243,note,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(8243,note)
            settings.edit().remove("last_guard_error").apply()
            ui.removeCallbacks(polling)
            ui.post(polling)
        } catch(e:Exception) {
            settings.edit().putBoolean("active",false)
                .putString("last_guard_error","تعذر تشغيل خدمة المراقبة: "+e.javaClass.simpleName).apply()
            Toast.makeText(this,"تعذّر تشغيل المراقبة؛ راجع شاشة التشخيص",Toast.LENGTH_LONG).show()
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }
    private fun checkForeground(pkg:String) {
        if(pkg!=lastForeground) {
            lastForeground=pkg
            if(pkg!=granted)granted=null
        }
        if(MainActivity.foreground || pkg==packageName || shouldExclude(pkg)){
            hideOverlay()
            return
        }
        if(!settings.getBoolean("active",false) || !Settings.canDrawOverlays(this)){
            hideOverlay();return
        }
        val allowOnly=settings.getInt("mode",0)==0
        val choice=settings.getStringSet(if(allowOnly)"allow_packages" else "block_packages",emptySet()).orEmpty()
        val blocked=if(allowOnly)pkg !in choice else pkg in choice
        if(!blocked || pkg==granted){hideOverlay();return}
        if(overlayFor==pkg && overlay!=null)return
        showLock(pkg)
    }
    private fun shouldExclude(pkg:String):Boolean {
        return pkg=="android" || pkg=="com.android.systemui" ||
            pkg=="com.android.settings" || pkg=="com.miui.securitycenter" ||
            pkg=="com.google.android.permissioncontroller" ||
            pkg=="com.android.permissioncontroller" ||
            pkg.startsWith("com.google.android.inputmethod") ||
            pkg.startsWith("com.android.inputmethod") ||
            pkg=="com.miui.home" || pkg=="com.android.launcher3" ||
            pkg=="com.google.android.apps.nexuslauncher" ||
            pkg=="com.google.android.packageinstaller"
    }
    fun refresh() {
        if(MainActivity.foreground || !settings.getBoolean("active",false)) hideOverlay()
        else lastForeground?.let{checkForeground(it)}
    }
    fun hideOverlay() {
        try{overlay?.let{wm.removeViewImmediate(it)}}catch(_:Exception){}
        overlay=null;overlayFor=null;digits="";pinView=null;busy=false
    }
    fun grantUnlock(pkg:String) {
        if(pkg.isBlank() || !settings.getBoolean("active",false))return
        granted=pkg
        hideOverlay()
    }
    override fun onDestroy() {
        ui.removeCallbacks(polling)
        hideOverlay()
        checks.shutdownNow()
        io.shutdown()
        instance=null
        super.onDestroy()
    }
    private fun dp(v:Int)=(v*resources.displayMetrics.density+0.5f).toInt()
    private fun bg(color:Int,r:Int=18)=GradientDrawable().apply {
        setColor(color);cornerRadius=dp(r).toFloat()
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
        line("هذا التطبيق محمي",25f,ink,true)
        val appName=try{packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg,0)).toString()}
            catch(_:Exception){pkg}
        line(appName,18f,dim)
        line("أدخل رمز الحماية لفتح التطبيق",14f,dim)
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
            text="التحقق بالبصمة أو الوجه"
            textSize=14f;setTextColor(Color.rgb(188,167,255))
            gravity=Gravity.CENTER;setPadding(0,dp(18),0,dp(12))
            setOnClickListener{
                if(!settings.getBoolean("bio_enabled",false)) {
                    Toast.makeText(this@GuardService,"يُرجى تفعيل التحقق البيومتري من الإعدادات أولاً",Toast.LENGTH_LONG).show()
                } else {
                    try {
                        val intent=android.content.Intent(this@GuardService,UnlockActivity::class.java)
                            .putExtra("target_pkg",pkg).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                        hideOverlay()
                        startActivity(intent)
                    } catch(e:Exception) {
                        Toast.makeText(this@GuardService,"تعذر التحقق البيومتري، استخدم رمز الحماية",Toast.LENGTH_SHORT).show()
                        showLock(pkg)
                    }
                }
            }
        }
        root.addView(biom)
        val params=WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_FULLSCREEN,
            android.graphics.PixelFormat.OPAQUE
        )
        params.gravity=Gravity.CENTER
        try {
            wm.addView(root,params)
            overlay=root;overlayFor=pkg
        } catch(e:Exception) {
            overlay=null;overlayFor=null
            settings.edit().putString("last_guard_error","تعذر عرض شاشة القفل: "+e.javaClass.simpleName).apply()
        }
    }
    private fun verify(pkg:String) {
        if(busy || digits.length<6) {
            if(digits.length<6)Toast.makeText(this,"يرجى إدخال رمز الحماية كاملاً",Toast.LENGTH_SHORT).show()
            return
        }
        busy=true
        val value=digits
        digits="";pinView?.text="جارٍ التحقق…"
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
                    pinView?.text=if(now<next)"انتظر قبل إعادة المحاولة" else "رمز الحماية غير صحيح"
                    Toast.makeText(this,"لم يتم فتح التطبيق",Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}