plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
 namespace="com.r4.qaflshamil"
 compileSdk=36
 defaultConfig {
  applicationId="com.r4.qaflshamil"
  minSdk=29
  targetSdk=35
  versionCode=3
  versionName="0.2.0-beta"
 }
 compileOptions {
  sourceCompatibility=JavaVersion.VERSION_17
  targetCompatibility=JavaVersion.VERSION_17
 }
 kotlinOptions { jvmTarget="17" }
}