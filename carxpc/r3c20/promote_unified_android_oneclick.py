#!/usr/bin/env python3
"""R3C20: patch exact previously source-pinned Android v24 MainActivity into
one-click real physical Android regression batch v25, preserving all controls.
"""
from pathlib import Path
import re,shutil,sys
project=Path(sys.argv[1])
root=project/"app/src/main/java/com/r4/carxpc"
activity=root/"MainActivity.java"
gradle=project/"app/build.gradle"
source=Path("carxpc/r3c20/android/CarXUnifiedBatch.java")
assert source.is_file()
target=root/"CarXUnifiedBatch.java"
assert not target.exists(),"Existing unified runner must not be overwritten"
shutil.copyfile(source,target)

s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+24\b','versionCode 25',s)
assert n==1,("VERSION24_SOURCE_NOT_FOUND",n)
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.25-r3c20-oneclick-device-batch'",s)
assert n==1,("VERSIONNAME_REWRITE",n)
gradle.write_text(s)

s=activity.read_text()
def rep(a,b):
    global s
    n=s.count(a)
    assert n==1,("EXPECTED_ONE_MAINACTIVITY_ANCHOR",n,a[:85])
    s=s.replace(a,b)
rep('private Button wineElfBtn; private JSONObject lastWineElf;',
    'private Button wineElfBtn; private JSONObject lastWineElf;\n  private Button unifiedBatchBtn; private JSONObject lastUnifiedBatch;')
rep('    wineElfBtn.setOnClickListener(v->beginWineElfPreflight());',
'''    wineElfBtn.setOnClickListener(v->beginWineElfPreflight());
    addText("09 | R3-C20 اختبار واحد لجميع مراحل الربط والتشخيص",17,ACCENT,true);
    addText("ضغط واحد يجري الاختبارات الحقيقية لـFEX وGNU 12/12 وWine ELF وVulkan، ويكتب أوّل فشل والمرحلة التالية. مرحلة Wine التنفيذية تبقى معلّمة بوضوح إذا لم يتوفر جسر Linux x64 الكامل.",13,MUTED,false);
    unifiedBatchBtn=button("بدء الاختبار الموحد الكامل — تقرير JSON واحد");
    unifiedBatchBtn.setOnClickListener(v->beginUnifiedBatch());''')
rep('      r.put("wine_elf_preflight",lastWineElf==null?JSONObject.NULL:lastWineElf);',
'''      r.put("wine_elf_preflight",lastWineElf==null?JSONObject.NULL:lastWineElf);
      r.put("unified_runtime_batch",lastUnifiedBatch==null?JSONObject.NULL:lastUnifiedBatch);''')
rep('  private void show(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}',
'''  private void beginUnifiedBatch(){
    if(busy)return;
    busy=true;
    unifiedBatchBtn.setEnabled(false);
    exportBtn.setEnabled(false);
    final android.view.Surface testSurface =
        surfaceReady && vulkanSurface!=null ?
        vulkanSurface.getHolder().getSurface() : null;
    status.setText("R3-C20: الاختبار الموحد يعمل: FEX الحقيقي وGNU الأصلي وملفات Wine وVulkan؛ الرجاء عدم إغلاق التطبيق.");
    worker.execute(()->{
      JSONObject j;
      try{
        j=CarXUnifiedBatch.run(getApplicationContext(),testSurface);
      }catch(Throwable t){
        j=new JSONObject();
        try{
          j.put("schema","r4.carx.r3c20.android-oneclick-gates.v1")
           .put("fatal_runner_error",t.getClass().getName())
           .put("fatal_runner_detail",String.valueOf(t.getMessage()))
           .put("native_android_wine_guest_process_executed",false)
           .put("windows_pe_vm_tls_writefile_android_executed",false)
           .put("carx_game_boot_proven",false);
        }catch(Exception ignored){}
      }
      final JSONObject data=j;
      handler.post(()->{
        busy=false;
        unifiedBatchBtn.setEnabled(true);
        lastUnifiedBatch=data;
        refreshReport();
        JSONObject stop=data.optJSONObject("first_stop");
        String failure=stop==null?"none":stop.optString("id","UNKNOWN")+": "+stop.optString("reason","UNKNOWN");
        status.setText("اكتملت الدفعة الواحدة. الناجح: "+data.optInt("pass_count",0)+
          " | أول توقف: "+failure+
          " | صدر التقرير JSON لتحديد المرحلة القادمة. نجاح فحص Wine لا يعني تشغيل Windows.");
      });
    });
  }

  private void show(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}''')
assert 'versionCode 25' in gradle.read_text()
activity.write_text(s)
for marker in ['beginUnifiedBatch()','unified_runtime_batch','CarXUnifiedBatch.run','native_android_wine_guest_process_executed']:
    assert marker in s,marker
print("CARX_R3C20_REAL_ANDROID_ONECLICK_BATCH_V25_SOURCE_PATCH_PASS")
