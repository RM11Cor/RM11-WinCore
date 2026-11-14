#!/usr/bin/env python3
"""Promote SHA-pinned original CarX Android v23 to R3C19 Wine ELF preflight v24.

Preserves FEX upstream native libraries and existing R3C15 test06.
No Wine/Win64 PE execution is represented by these read-only checks.
"""
from pathlib import Path
import re,shutil,sys
root=Path(sys.argv[1])
gradle=root/"app/build.gradle"
activity=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
probe=Path("carxpc/r3c19/android/WineGuestElfPreflight.java")
assert probe.is_file()
target=activity.parent/probe.name
assert not target.exists(),("PREEXISTING_PROBE",target)
shutil.copyfile(probe,target)
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+23\b','versionCode 24',s)
assert n==1,("EXPECTED_R3C18_VERSION23",n)
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.24-r3c19-wine-elf-amd64-preflight'",s)
assert n==1
gradle.write_text(s)
s=activity.read_text()
def rep(a,b):
    global s
    n=s.count(a)
    assert n==1,("R3C19_ANDROID_ACTIVITY_ANCHOR",a[:90],n)
    s=s.replace(a,b)

rep("private Button guestRootfsBtn; private JSONObject lastRootfs;",
    "private Button guestRootfsBtn; private JSONObject lastRootfs;\n  private Button wineElfBtn; private JSONObject lastWineElf;")
rep('    guestRootfsBtn.setOnClickListener(v->{',
    '''    guestRootfsBtn.setOnClickListener(v->{''')
# New button follows end of R3C18 rootfs button onCreate() callback.
rep("      startActivityForResult(i,PICK_WINE_ROOTFS);\n    });",
'''      startActivityForResult(i,PICK_WINE_ROOTFS);
    });
    addText("08 | R3-C19 فحص ملفات Wine x64 التنفيذية داخل RootFS",17,ACCENT,true);
    addText("بعد استيراد الحزمة: يفحص wine64 وGNU ld-linux وkernel32 ومكتبات DT_NEEDED وبصماتها الأصلية. قراءة فقط؛ ماكو تنفيذ Windows أو تشغيل اللعبة.",13,MUTED,false);
    wineElfBtn=button("فحص Wine x64 ELF وملفات Windows الأصلية");
    wineElfBtn.setOnClickListener(v->beginWineElfPreflight());''')
rep('      r.put("wine_guest_rootfs",lastRootfs==null?JSONObject.NULL:lastRootfs);',
'''      r.put("wine_guest_rootfs",lastRootfs==null?JSONObject.NULL:lastRootfs);
      r.put("wine_elf_preflight",lastWineElf==null?JSONObject.NULL:lastWineElf);''')
rep('  private void show(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}',
'''  private void beginWineElfPreflight(){
    if(busy)return;
    busy=true;wineElfBtn.setEnabled(false);exportBtn.setEnabled(false);
    status.setText("R3-C19: جاري فحص Wine ELF x86-64 وGNU ld.so وkernel32 وبصمات SHA-256؛ بدون تشغيل...");
    worker.execute(()->{
      JSONObject result=new JSONObject();
      try{
        WineGuestElfPreflight.Result p=WineGuestElfPreflight.inspect(getFilesDir().toPath());
        result.put("schema","r4.carx.r3c19.android-wine-guest-elf-preflight.v1")
          .put("success",p.realX86LinuxElfVerified &&
             p.guestInterpreterElfVerified && p.kernel32Pe64Amd64Verified &&
             p.immediateNeededLibrariesPresent)
          .put("source_rootfs_sha256",p.rootfsSha256)
          .put("wine64_elf_sha256",p.wineElfSha256)
          .put("gnu_ldso_elf_sha256",p.interpreterElfSha256)
          .put("kernel32_pe_sha256",p.kernel32PeSha256)
          .put("wine_elf_machine","AMD64")
          .put("wine_linux_interpreter",p.interpreter)
          .put("wine_pt_load_count",p.winePtLoadSegments)
          .put("ldso_pt_load_count",p.interpreterPtLoadSegments)
          .put("wine_dt_needed",new org.json.JSONArray(p.wineDtNeeded))
          .put("unresolved_dt_needed",new org.json.JSONArray(p.unresolvedImmediateLibraries))
          .put("guest_elf_readonly_metadata_checked",true)
          .put("dt_needed_immediate_closure_available",p.immediateNeededLibrariesPresent)
          .put("android_wine_executed",false)
          .put("wine64_linux_guest_process_executed",false)
          .put("win64_pe_android_executed",false)
          .put("carx_game_boot_proven",false);
      }catch(Throwable t){
        try{
          result.put("schema","r4.carx.r3c19.android-wine-guest-elf-preflight.v1")
            .put("success",false)
            .put("error_type",t.getClass().getSimpleName())
            .put("error_code",String.valueOf(t.getMessage()))
            .put("guest_elf_readonly_metadata_checked",false)
            .put("android_wine_executed",false)
            .put("wine64_linux_guest_process_executed",false)
            .put("win64_pe_android_executed",false)
            .put("carx_game_boot_proven",false);
        }catch(Exception ignored){}
      }
      final JSONObject finished=result;
      handler.post(()->{
        busy=false;wineElfBtn.setEnabled(true);lastWineElf=finished;
        refreshReport();
        status.setText(finished.optBoolean("success",false)
          ? "نجح R3-C19: Wine ELF x64 والمحمّل وkernel32 والمكتبات المباشرة موثقة. تشغيل Wine على أندرويد لم يبدأ بعد."
          : "فحص Wine ELF رفض ملفاً أو لم يجد RootFS مثبتاً؛ السبب بالتقرير JSON.");
      });
    });
  }

  private void show(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}''')
activity.write_text(s)
assert s.count('wine_elf_preflight')>=1
assert s.count('wine64_linux_guest_process_executed')>=2
assert s.count('win64_pe_android_executed')>=2
assert "versionCode 24" in gradle.read_text()
print("CARX_R3C19_ANDROID_JAVA_DEVICE_READONLY_WINE_ELF_PREFLIGHT_V24_PATCH_PASS")
