plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace="com.r4.qaflshamil"
 compileSdk=36
 defaultConfig {
  applicationId="com.moammalsaad.alquflshamil"
  minSdk=29
  targetSdk=36
  versionCode=1
  versionName="1.0.0-rc1"
 }
 compileOptions {
  sourceCompatibility=JavaVersion.VERSION_17
  targetCompatibility=JavaVersion.VERSION_17
 }
 kotlinOptions { jvmTarget="17" }
}