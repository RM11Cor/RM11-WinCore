#!/usr/bin/env python3
"""Promote source-reconstructed CarX Android app v22->23 for real Wine data import.
Only Java import/diagnostics; no claims of Windows PE execution on Android.
"""
from pathlib import Path
import re,shutil,sys
root=Path(sys.argv[1])
manifest=root/"app/src/main/AndroidManifest.xml"
gradle=root/"app/build.gradle"
activity=root/"app/src/main/java/com/r4/carxpc/MainActivity.java"
source=Path("carxpc/r3c18/android/GuestRootfsInstaller.java")
assert source.is_file(),source
target=activity.parent/source.name
assert not target.exists(),target
shutil.copyfile(source,target)
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+22\b','versionCode 23',s)
assert n==1,("EXPECTED_R3C15_VERSION22",n)
s,n=re.subn(r"versionName\s+'[^']+'","versionName '0.23-r3c18-owned-wine-rootfs'",s)
assert n==1
gradle.write_text(s)
s=activity.read_text()
def repl(a,b):
    global s
    n=s.count(a)
    assert n==1,("SOURCE_ANCHOR_COUNT",n,a[:100])
    s=s.replace(a,b)
repl("import java.io.OutputStream;","import java.io.OutputStream;\nimport java.io.InputStream;")
repl("private static final int PICK_FOLDER=101,CREATE_REPORT=102;",
     "private static final int PICK_FOLDER=101,CREATE_REPORT=102,PICK_WINE_ROOTFS=103;")
repl("private int dp(int v){",
'''private Button guestRootfsBtn; private JSONObject lastRootfs;
  private int dp(int v){''')
repl("    continuationBtn.setOnClickListener(v->beginOriginalLdsoContinuation());",
'''    continuationBtn.setOnClickListener(v->beginOriginalLdsoContinuation());
    addText("07 | R3-C18 تجهيز ملفات بيئة Wine x64 داخل مساحة التطبيق",17,ACCENT,true);
    addText("اختيار أرشيف Linux x64 الموثق فقط. يفحص SHA-256 وينشئ RootFS داخل ملفات التطبيق بأمان. لا يشغّل Wine أو Windows أو CarX.",13,MUTED,false);
    guestRootfsBtn=button("اختيار ملف Wine RootFS بصيغة tar.gz");
    guestRootfsBtn.setOnClickListener(v->{
      if(busy)return;
      Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
      i.addCategory(Intent.CATEGORY_OPENABLE);
      i.setType("*/*");
      i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      startActivityForResult(i,PICK_WINE_ROOTFS);
    });''')
repl("    if(req==CREATE_REPORT){",
'''    if(req==PICK_WINE_ROOTFS){
      final Uri chosen=data.getData();
      long required=java.nio.file.Files.exists(
        new java.io.File(getFilesDir(),GuestRootfsInstaller.ROOTFS_NAME).toPath())
        ? 2700000000L : 1400000000L;
      long available=getFilesDir().getUsableSpace();
      if(available<required){
        status.setText("لا توجد مساحة كافية: يحتاج استيراد Wine مساحة خالية بحد أدنى "+(required/1000000000.0)+" GB؛ المتوفر "+(available/1000000000.0)+" GB.");
        return;
      }
      busy=true;
      guestRootfsBtn.setEnabled(false);
      status.setText("R3-C18: جاري استيراد Wine RootFS والتحقق من SHA-256 وكل المسارات دون صلاحيات root...");
      worker.execute(()->{
        JSONObject importResult=new JSONObject();
        try(InputStream in=getContentResolver().openInputStream(chosen)){
          if(in==null)throw new java.io.IOException("NULL_DOCUMENT_STREAM");
          GuestRootfsInstaller.Receipt receipt=GuestRootfsInstaller.install(in,getFilesDir().toPath());
          importResult.put("schema","r4.carx.r3c18.owned-guest-rootfs-install.v1")
            .put("status","SOURCE_SHA256_VERIFIED_STAGED_DATA_ONLY")
            .put("success",true)
            .put("sha256",receipt.sha256)
            .put("entries",receipt.entries)
            .put("regular_bytes",receipt.regularBytes)
            .put("symbolic_links",receipt.symlinks)
            .put("hardlinks",receipt.hardlinks)
            .put("storage","ANDROID_APP_PRIVATE_FILES")
            .put("guest_rootfs_installed",true)
            .put("wine_android_executed",false)
            .put("win64_pe_android_executed",false)
            .put("carx_game_boot_proven",false);
        }catch(Throwable e){
          try{
            importResult.put("schema","r4.carx.r3c18.owned-guest-rootfs-install.v1")
              .put("success",false)
              .put("status","IMPORT_REJECTED_OR_FAILED")
              .put("error_type",e.getClass().getSimpleName())
              .put("detail",String.valueOf(e.getMessage()))
              .put("wine_android_executed",false)
              .put("win64_pe_android_executed",false)
              .put("carx_game_boot_proven",false);
          }catch(Exception ignored){}
        }
        final JSONObject finalResult=importResult;
        handler.post(()->{
          busy=false;guestRootfsBtn.setEnabled(true);lastRootfs=finalResult;
          refreshReport();
          status.setText(finalResult.optBoolean("success",false)
            ? "نجح تثبيت ملفات Wine RootFS الأصلية داخل التطبيق؛ تشغيل Wine وWindows لم يبدأ بعد."
            : "فشل أو رُفض أرشيف Wine. السبب مسجل بتقرير JSON، والنسخة السليمة السابقة محفوظة.");
        });
      });
    }
    if(req==CREATE_REPORT){''')
repl('      r.put("game_scan",',
     '      r.put("wine_guest_rootfs",lastRootfs==null?JSONObject.NULL:lastRootfs);\n      r.put("game_scan",')
activity.write_text(s)
assert s.count("PICK_WINE_ROOTFS")>=3
assert "wine_android_executed\",false" in s
assert "win64_pe_android_executed\",false" in s
assert "carx_game_boot_proven\",false" in s
assert (root/"app/src/main/java/com/r4/carxpc/GuestRootfsInstaller.java").is_file()
print("CARX_R3C18_ANDROID_APP_WINE_GUEST_ROOTFS_SAF_IMPORT_AND_JSON_GATE_PATCH_PASS")
