package com.r4.qaflshamil

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.widget.TextView
import android.widget.Toast

class UnlockActivity: Activity() {
    private var target:String=""
    private val cancel=CancellationSignal()
    private var granted=false
    override fun onCreate(state:Bundle?) {
        super.onCreate(state)
        target=intent.getStringExtra("target_pkg").orEmpty()
        val status=TextView(this).apply{
            text="القفل الشامل\nالتحقق ببصمة الجهاز أو الوجه";textSize=21f
            gravity=android.view.Gravity.CENTER
            setTextColor(android.graphics.Color.WHITE)
            setBackgroundColor(android.graphics.Color.rgb(11,19,42))
        }
        setContentView(status)
        if(target.isBlank() || !getSharedPreferences("arabic_lock_settings",MODE_PRIVATE).getBoolean("bio_enabled",false)){
            finish();return
        }
        try {
            val m=getSystemService(BIOMETRIC_SERVICE) as BiometricManager
            val result=if(Build.VERSION.SDK_INT>=30)
                m.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            else @Suppress("DEPRECATION") m.canAuthenticate()
            if(result!=BiometricManager.BIOMETRIC_SUCCESS) {
                Toast.makeText(this,"التحقق الحيوي غير متاح؛ استخدم الرمز",Toast.LENGTH_LONG).show()
                finish();return
            }
            val b=BiometricPrompt.Builder(this)
                .setTitle("القفل الشامل")
                .setSubtitle("افتح التطبيق باستخدام تحقق النظام")
                .setNegativeButton("إلغاء",mainExecutor){_,_->finish()}
            if(Build.VERSION.SDK_INT>=30)b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            b.build().authenticate(cancel,mainExecutor,object:BiometricPrompt.AuthenticationCallback(){
                override fun onAuthenticationSucceeded(result:BiometricPrompt.AuthenticationResult) {
                    granted=true
                    GuardService.instance?.grantUnlock(target)
                    finish()
                }
                override fun onAuthenticationError(errorCode:Int,errString:CharSequence) {
                    if(!granted)Toast.makeText(this@UnlockActivity,"استخدم رمز القفل إذا ما اشتغل التحقق",Toast.LENGTH_SHORT).show()
                    finish()
                }
            })
        }catch(e:Exception){
            Toast.makeText(this,"التحقق الحيوي ما اشتغل؛ استخدم الرمز",Toast.LENGTH_SHORT).show()
            finish()
        }
    }
    override fun onDestroy() {
        cancel.cancel()
        super.onDestroy()
    }
}