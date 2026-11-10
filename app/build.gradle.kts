plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace="com.r4.qaflshamil"
 compileSdk=36
 defaultConfig {
  applicationId="com.moammalsaad.alquflshamil.stable"
  minSdk=28
  targetSdk=36
  versionCode=5
  versionName="1.2.1"
 }
 compileOptions {
  sourceCompatibility=JavaVersion.VERSION_17
  targetCompatibility=JavaVersion.VERSION_17
 }
 kotlinOptions { jvmTarget="17" }
}