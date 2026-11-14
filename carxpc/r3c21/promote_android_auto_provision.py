#!/usr/bin/env python3
"""R3C21. Upgrade signed Android v25 one-click batch to optional original
Ubuntu Wine guest data HTTPS provisioning, and make summary sections consistent.
Does not add or claim generalized Wine/Windows guest process execution.
"""
from pathlib import Path
import re,shutil,sys
app=Path(sys.argv[1])
java=app/"app/src/main/java/com/r4/carxpc"
activity=java/"MainActivity.java"
gradle=app/"app/build.gradle"
manifest=app/"app/src/main/AndroidManifest.xml"
provider=Path("carxpc/r3c21/android/WineGuestHttpProvisioner.java")
for p in [activity,gradle,manifest,provider]:
    assert p.is_file(),p
target=java/provider.name
assert not target.exists(),"Duplicate network provisioner"
shutil.copyfile(provider,target)
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+25\b','versionCode 26',s)
assert n==1,("EXPECTED_SIGNED_VERSION25",n)
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.26-r3c21-oneclick-wine-auto-provision'",s)
assert n==1
gradle.write_text(s)
m=manifest.read_text()
assert '<manifest xmlns:android=' in m
assert 'android.permission.INTERNET' not in m
m=m.replace('    <application ', '    <uses-permission android:name="android.permission.INTERNET" />\n    <application ',1)
assert m.count('android.permission.INTERNET')==1
manifest.write_text(m)
s=activity.read_text()
def rep(a,b):
    global s
    n=s.count(a)
    assert n==1,("EXPECTED_UNIQUE_R3C20_ANCHOR",n,a[:110])
    s=s.replace(a,b)

rep('    unifiedBatchBtn.setOnClickListener(v->beginUnifiedBatch());',
'''    unifiedBatchBtn.setOnClickListener(v->beginUnifiedBatchWithOptionalProvision());''')
rep('  private void beginUnifiedBatch(){',
'''  private void beginUnifiedBatchWithOptionalProvision(){
    if(busy)return;
    boolean installed=new java.io.File(getFilesDir(),
      GuestRootfsInstaller.ROOTFS_NAME+"/.r4-rootfs-receipt").isFile();
    if(installed){
      beginUnifiedBatch(false);
      return;
    }
    long free=getFilesDir().getUsableSpace();
    String notice="حزمة Wine Linux x64 الأصلية غير مثبتة. تقدر تختبر الموجود بدون تحميل، " +
      "أو توافق على تحميل 517 MB من GitHub إلى مساحة التطبيق، " +
      "وفك تقريباً 1.26 GB من الملفات مع التحقق من SHA-256. " +
      "التحميل يتطلب 1.75 GB مساحة خالية على الأقل. المساحة المتوفرة: "+
      String.format(java.util.Locale.ROOT,"%.2f",free/1000000000.0)+" GB. "+
      "حتى بعد تثبيت البيانات، تنفيذ Wine الكامل على أندرويد ما زال يحتاج جسر العمليات.";
    new android.app.AlertDialog.Builder(this)
      .setTitle("R3-C21 — اختبار موحد مع ملفات Wine")
      .setMessage(notice)
      .setPositiveButton("تحميل ملفات Wine وفحص الكل",(dialog,which)->beginUnifiedBatch(true))
      .setNeutralButton("اختبار بدون تحميل",(dialog,which)->beginUnifiedBatch(false))
      .setNegativeButton("إلغاء",null)
      .show();
  }

  private void beginUnifiedBatch(boolean autoProvision){''')

old='''    worker.execute(()->{
      JSONObject j;
      try{
        j=CarXUnifiedBatch.run(getApplicationContext(),testSurface);
      }catch(Throwable t){'''
neu='''    worker.execute(()->{
      JSONObject provisioning=null;
      if(autoProvision){
        provisioning=new JSONObject();
        try{
          GuestRootfsInstaller.Receipt receipt=WineGuestHttpProvisioner.provision(
            getApplicationContext(),(bytes,total)->handler.post(()->{
              long percent=total>0?(100*bytes/total):0;
              status.setText("R3-C21: تحميل Wine والتحقق من المصدر ... "+percent+"% "+
                " (تقريباً "+(bytes/1000000)+" / "+(total/1000000)+" MB)");
            }));
          provisioning.put("schema","r4.carx.r3c21.real-original-guest-data-download.v1")
             .put("success",true)
             .put("source","HTTPS_GITHUB_RELEASE_EXACT_SOURCE_SHA")
             .put("expected_bytes",WineGuestHttpProvisioner.ORIGINAL_ARCHIVE_LENGTH)
             .put("verified_sha256",receipt.sha256)
             .put("entries",receipt.entries)
             .put("regular_bytes",receipt.regularBytes)
             .put("symlinks",receipt.symlinks)
             .put("hardlinks",receipt.hardlinks)
             .put("app_private_storage",true)
             .put("guest_linux_wine_executed",false)
             .put("windows_pe_executed",false);
        }catch(Throwable e){
          try{
            provisioning.put("schema","r4.carx.r3c21.real-original-guest-data-download.v1")
              .put("success",false)
              .put("download_or_import_error_type",e.getClass().getName())
              .put("reason",String.valueOf(e.getMessage()))
              .put("original_archive_size_bytes",WineGuestHttpProvisioner.ORIGINAL_ARCHIVE_LENGTH)
              .put("guest_linux_wine_executed",false)
              .put("windows_pe_executed",false);
          }catch(Exception ignored){}
        }
      }
      final JSONObject provisioningResult=provisioning;
      JSONObject j;
      try{
        j=CarXUnifiedBatch.run(getApplicationContext(),testSurface);
        if(provisioningResult!=null)
          j.put("wine_guest_data_auto_provision",provisioningResult);
      }catch(Throwable t){'''
rep(old,neu)
oldCallback='''        lastUnifiedBatch=data;
        refreshReport();
        JSONObject stop=data.optJSONObject("first_stop");'''
newCallback='''        lastUnifiedBatch=data;
        if(provisioningResult!=null)lastRootfs=provisioningResult;
        // Propagate results already RUN in this batch to legacy top-level
        // fields. Do not rerun device tests, and do not claim Wine ran.
        org.json.JSONArray measured=data.optJSONArray("stages");
        if(measured!=null){
          for(int i=0;i<measured.length();i++){
            JSONObject stage=measured.optJSONObject(i);
            if(stage==null)continue;
            String id=stage.optString("id","");
            JSONObject evidence=stage.optJSONObject("evidence");
            if(evidence==null)continue;
            if("01_FEXCORE_ORIGINAL".equals(id))lastFex=evidence;
            if("02_GNU_LDSO_LIBC_12_OF_12".equals(id))lastContinuation=evidence;
            if("05_ANDROID_VULKAN_ICD".equals(id))lastVulkan=evidence;
            if("06_ANDROID_VULKAN_SWAPCHAIN_CLEAR_PRESENT".equals(id))
              lastPresentation=evidence;
          }
        }
        refreshReport();
        JSONObject stop=data.optJSONObject("first_stop");'''
rep(oldCallback,newCallback)
oldComp='      components.put("wine",new JSONObject().put("status","NOT_PACKAGED").put("runtime_test_passed",false));'
newComp='''      String wineState=(lastUnifiedBatch!=null &&
        lastUnifiedBatch.optBoolean("rootfs_metadata_verified",false))
          ? "GUEST_DATA_VERIFIED_NATIVE_ANDROID_WINE_PROCESS_ADAPTER_MISSING"
          : "GUEST_DATA_NOT_PROVEN_ON_ANDROID";
      components.put("wine",new JSONObject().put("status",wineState)
        .put("runtime_test_passed",false));'''
rep(oldComp,newComp)
assert 'unified_runtime_batch' in s
assert 'lastFex=evidence' in s and 'lastVulkan=evidence' in s
assert 'CarXUnifiedBatch.run(' in s
assert 'android.permission.INTERNET' in manifest.read_text()
assert 'versionCode 26' in gradle.read_text()
activity.write_text(s)
print("CARX_R3C21_OPTIONAL_REAL_SOURCE_WINE_ARCHIVE_DOWNLOAD_ONECLICK_AND_TOPLEVEL_REPORT_RECONCILED")
