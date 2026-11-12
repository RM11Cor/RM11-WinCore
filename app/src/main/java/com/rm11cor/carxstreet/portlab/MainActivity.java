package com.rm11cor.carxstreet.portlab;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity {
    private static final int PICK_GAME=5001;
    private static final int EXPORT_JSON=5002;
    private static final int EXPORT_AOT_CODE=5003;
    private static final int BG=0xFF0B1018;
    private static final int CARD=0xFF182231;
    private static final int BLUE=0xFF56C6F3;
    private static final int SUB=0xFFAABAC9;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean abort=new AtomicBoolean(false);
    private volatile boolean scanning=false;
    private Uri tree;
    private String lastReport;
    private TextView status;
    private TextView details;
    private TextView folder;
    private Button copy;
    private Button export;
    private Button rescan;
    private Button aotSource;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        buildUi();
        SharedPreferences p=getPreferences(MODE_PRIVATE);
        String last=p.getString("selected_game_tree",null);
        if(last!=null) {
            try {
                tree=Uri.parse(last);
                folder.setText("المجلد محفوظ من الجلسة السابقة. اضغط إعادة الفحص.");
                rescan.setEnabled(true);
                aotSource.setEnabled(true);
            }catch(Exception ignored){}
        }
    }

    private void buildUi() {
        ScrollView scroll=new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20),dp(32),dp(20),dp(30));
        root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        scroll.addView(root);
        TextView eyebrow=label("RM11Cor • Android ARM64",13,BLUE,true);
        root.addView(eyebrow);
        TextView title=label("CARX STREET",32,Color.WHITE,true);
        root.addView(title);
        root.addView(label("PC PORT LAB v1.4  /  إغلاق فجوات كود CarX",15,SUB,false));
        gap(root,24);
        LinearLayout banner=new LinearLayout(this);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setPadding(dp(18),dp(18),dp(18),dp(18));
        banner.setBackground(round(CARD,18));
        root.addView(banner);
        banner.addView(label("المرحلة 13 — استخراج كود الفجوات التنفيذية",19,Color.WHITE,true));
        gap(banner,8);
        banner.addView(label("من كود CarX v1.3 الحقيقي اكتشفنا 146 فجوة بين مقاطع الأب والتابع، مجموعها 47,416 بايت وأكبرها 2,145 بايت. نأخذ هذه البايتات الأصلية مع SHA حتى نبني CFG متصل ونعرف التبعيات الفعلية.",14,SUB,false));
        gap(root,16);
        folder=label("ما مختار مجلد اللعبة بعد",14,SUB,false);
        root.addView(folder);
        gap(root,12);
        Button choose=button("اختيار مجلد CarX Street PC",BLUE,0xFF071520);
        root.addView(choose);
        choose.setOnClickListener(v -> chooseFolder());
        gap(root,9);
        rescan=button("إعادة فحص نفس المجلد",CARD,Color.WHITE);
        rescan.setEnabled(false);
        root.addView(rescan);
        rescan.setOnClickListener(v -> {if(tree!=null)scan();});
        gap(root,9);
        aotSource=button("استخراج كود CarX + الفجوات التنفيذية",BLUE,0xFF071520);
        aotSource.setEnabled(false);
        root.addView(aotSource);
        aotSource.setOnClickListener(v -> requestAotCodeExport());
        gap(root,9);
        root.addView(label("يحفظ ZIP محدوداً من دوال GameAssembly ومعلومات Win64 .xdata الفعلية، ويتتبع روابط CHAININFO. لا يغيّر ملفات اللعبة ولا ينفذ كود Windows.",12,SUB,false));
        gap(root,20);
        LinearLayout reportCard=new LinearLayout(this);
        reportCard.setPadding(dp(16),dp(18),dp(16),dp(18));
        reportCard.setOrientation(LinearLayout.VERTICAL);
        reportCard.setBackground(round(0xFF131E2A,15));
        root.addView(reportCard);
        reportCard.addView(label("نتيجة فحص النسخة",18,Color.WHITE,true));
        gap(reportCard,8);
        status=label("جاهز لاختيار المجلد",14,BLUE,true);
        reportCard.addView(status);
        gap(reportCard,8);
        details=label("نقرأ ملف EXE وGameAssembly.dll وUnityPlayer.dll وحزم Unity وIL2CPP، ونسجل نتائج دون تعديل اللعبة.",13,SUB,false);
        reportCard.addView(details);
        gap(root,16);
        copy=button("نسخ تقرير JSON",CARD,Color.WHITE);
        copy.setEnabled(false);
        root.addView(copy);
        copy.setOnClickListener(v -> copyReport());
        gap(root,8);
        export=button("حفظ التقرير لإرساله بالمحادثة",CARD,Color.WHITE);
        export.setEnabled(false);
        root.addView(export);
        export.setOnClickListener(v -> saveReport());
        gap(root,22);
        root.addView(label("مسار التطوير",18,Color.WHITE,true));
        gap(root,8);
        root.addView(label("1. كشف بنية نسخة PC وموارد Windows.\n2. تقييم تحويل الموارد إلى Android وفحص الاعتمادات.\n3. محرك تنفيذ ARM64 أصلي مرخّص أو معاد بناؤه بصورة مستقلة.\n4. Vulkan والصوت وتحكم اللمس واليد.\n5. إثبات إقلاع اللعبة والوصول إلى أول إطار فعلي.",14,SUB,false));
        gap(root,12);
        root.addView(label("لا يتم تجاوز حماية Steam أو Easy Anti-Cheat. وضع اللعب الجماعي غير مدعوم بهذا النموذج.",12,0xFFFFC384,false));
        setContentView(scroll);
    }

    private int dp(int value) {return Math.round(getResources().getDisplayMetrics().density*value);}
    private GradientDrawable round(int color,int radius) {
        GradientDrawable d=new GradientDrawable();
        d.setColor(color);d.setCornerRadius(dp(radius));
        return d;
    }
    private TextView label(String s,int size,int color,boolean strong) {
        TextView t=new TextView(this);
        t.setText(s);t.setTextColor(color);t.setTextSize(size);
        t.setLineSpacing(dp(3),1f);
        t.setGravity(Gravity.START);
        if(strong)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        return t;
    }
    private Button button(String s,int color,int ink) {
        Button b=new Button(this);
        b.setText(s);b.setTextColor(ink);
        b.setAllCaps(false);
        b.setTextSize(15);
        b.setMinHeight(dp(52));
        b.setBackground(round(color,14));
        return b;
    }
    private void gap(LinearLayout parent,int units) {
        View v=new View(this);parent.addView(v,new LinearLayout.LayoutParams(1,dp(units)));
    }

    private void chooseFolder() {
        if(scanning)return;
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|
                   Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(i,PICK_GAME);
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null)return;
        if(request==PICK_GAME) {
            Uri uri=data.getData();
            try {
                getContentResolver().takePersistableUriPermission(
                    uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);
            }catch(Exception ignored) {}
            tree=uri;
            getPreferences(MODE_PRIVATE).edit().putString("selected_game_tree",uri.toString()).apply();
            folder.setText("تم اختيار مجلد اللعبة. جاري قراءة الملفات فقط...");
            rescan.setEnabled(true);
            aotSource.setEnabled(true);
            scan();
        }else if(request==EXPORT_AOT_CODE) {
            exportAotCode(data.getData());
        }else if(request==EXPORT_JSON && lastReport!=null) {
            try(OutputStream out=getContentResolver().openOutputStream(data.getData(),"w")) {
                if(out==null)throw new IllegalStateException("no output stream");
                out.write(lastReport.getBytes(StandardCharsets.UTF_8));
                out.flush();
                status.setText("تم حفظ تقرير الفحص — تقدر ترفعه هنا بالمحادثة");
            }catch(Exception ex) {
                status.setText("فشل حفظ التقرير: "+ex.getClass().getSimpleName());
            }
        }
    }

    private void scan() {
        if(tree==null||scanning)return;
        scanning=true;abort.set(false);
        status.setText("جاري فحص الملفات...");
        details.setText("نعالج عناصر المجلد بدون استخراج أو نسخ محتويات اللعبة.");
        copy.setEnabled(false);export.setEnabled(false);rescan.setEnabled(false);aotSource.setEnabled(false);
        final Uri selected=tree;
        worker.execute(() -> {
            try {
                JSONObject result=GameScanner.inspect(this,selected,new GameScanner.Progress() {
                    private int lastShown=0;
                    @Override public void onCount(int files,int dirs) {
                        if(files+dirs-lastShown>=1000) {
                            lastShown=files+dirs;
                            main.post(() -> status.setText("جاري الفحص: "+files+" ملف / "+dirs+" مجلد"));
                        }
                    }
                    @Override public boolean cancelled() {return abort.get();}
                });
                String json=result.toString(2);
                main.post(() -> {
                    lastReport=json;
                    scanning=false;
                    rescan.setEnabled(true);copy.setEnabled(true);export.setEnabled(true);aotSource.setEnabled(true);
                    JSONObject hits=result.optJSONObject("detect");
                    JSONObject count=result.optJSONObject("counts");
                    JSONObject machines=result.optJSONObject("machine");
                    JSONObject deep=result.optJSONObject("unity_deep_probe");
                    JSONObject meta=deep==null?null:deep.optJSONObject("global_metadata");
                    JSONObject serial=deep==null?null:deep.optJSONObject("unity_serialized_file_headers");
                    JSONObject sourceDeps=result.optJSONObject("windows_source_dependency_probe");
                    JSONObject codeDeps=sourceDeps==null?null:sourceDeps.optJSONObject("pc_executable_dependencies");
                    JSONObject assemblyDeps=codeDeps==null?null:codeDeps.optJSONObject("game_assembly");
                    JSONObject catalogDeps=sourceDeps==null?null:sourceDeps.optJSONObject("addressables_platform_references");
                    JSONObject reconcile=sourceDeps==null?null:sourceDeps.optJSONObject("windows64_asset_bundle_filename_reconciliation");
                    boolean matchVerified=reconcile!=null&&reconcile.optBoolean("fully_comparable");
                    int physicalOnly=reconcile==null?0:reconcile.optInt("physical_files_not_in_catalog_count");
                    int catalogOnly=reconcile==null?0:reconcile.optInt("catalog_names_missing_from_physical_files_count");
                    int distinctRefs=reconcile==null?0:reconcile.optInt("distinct_catalog_windows64_bundle_names");
                    int unsupportedPhysical=reconcile==null?0:
                            reconcile.optInt("unsupported_physical_bundle_basename_count");
                    int ambiguousCatalog=reconcile==null?0:
                            reconcile.optInt("ambiguous_windows64_reference_names");
                    String sourceAuditStatus=reconcile==null?"غير متاح":
                            reconcile.optString("audit_status","غير متاح");
                    int androidTargetPaths=reconcile==null?0:reconcile.optInt("android_target_path_reference_count");
                    int importCount=assemblyDeps==null?0:assemblyDeps.optJSONArray("static_import_library_names")==null?
                            0:assemblyDeps.optJSONArray("static_import_library_names").length();
                    String importStatus=assemblyDeps==null?"غير معروف":
                            assemblyDeps.optBoolean("pe_import_directory_complete")?"اكتمل":
                            "تعذر الفحص؛ راجع JSON";
                    int catalogReferences=catalogDeps==null?0:catalogDeps.optInt("internal_id_count");
                    int windowsReferences=catalogDeps==null?0:catalogDeps.optInt("standalone_windows64_references");
                    boolean catalogParsed=catalogDeps!=null&&catalogDeps.optBoolean("full_file_parsed");
                    JSONObject nativeProbe=result.optJSONObject("native_arm64_vulkan_preflight");
                    JSONObject nativeData=nativeProbe==null?null:nativeProbe.optJSONObject("native_runtime");
                    String gpuName=nativeData==null?"غير محدد":nativeData.optString("gpu_name","غير محدد");
                    boolean gpuWork=nativeProbe!=null&&nativeProbe.optBoolean("native_gpu_work_verified");
                    JSONObject clearGpu=nativeProbe==null?null:nativeProbe.optJSONObject("native_gpu_clear_readback");
                    String gpuStage=clearGpu==null?"لم يختبر":clearGpu.optString("stage","غير معروف");
                    boolean nativeArm=nativeProbe!=null&&nativeProbe.optBoolean("native_arm64_procedure_executed");
                    boolean vkReady=nativeProbe!=null&&nativeProbe.optBoolean("vulkan_instance_created");
                    org.json.JSONArray engineCandidates=serial==null?null:serial.optJSONArray("candidate_unity_editor_versions");
                    String engineVersion=(engineCandidates!=null && engineCandidates.length()>0)?
                            engineCandidates.optString(0):"غير مثبت من الملف";
                    org.json.JSONArray v=deep==null?null:deep.optJSONArray("sampled_bundle_unity_versions");
                    String sampleVersion=(v!=null&&v.length()>0)?v.optString(0):"غير معروف";
                    int bundleCount=deep==null?0:deep.optInt("windows64_bundle_count");
                    long metadataVersion=meta==null?-1:meta.optLong("metadata_version",-1);
                    boolean eligible=hits!=null&&hits.optBoolean("carx_pc_exe")
                                    &&hits.optBoolean("il2cpp_game_assembly_windows")
                                    &&hits.optBoolean("carx_street_data_directory");
                    status.setText(eligible ? "نسخة PC وUnity IL2CPP مكتشفة" :
                        "الفحص اكتمل؛ ناقص دليل على بعض ملفات نسخة PC");
                    details.setText("الملفات: "+(count==null?0:count.optInt("files"))+
                        "\nالمجلدات: "+(count==null?0:count.optInt("folders"))+
                        "\nEXE: "+(machines==null?"":machines.optString("carx_exe"))+
                        "\nGameAssembly: "+(machines==null?"":machines.optString("gameassembly_dll"))+
                        "\nUnity + IL2CPP: "+eligible+
                        "\nإصدار IL2CPP metadata: "+(metadataVersion>=0?metadataVersion:"غير معروف")+
                        "\nUnityFS Windows bundles: "+bundleCount+
                        "\nUnityFS header (معلومات عامة): "+sampleVersion+
                        "\nإصدار المحرك من globalgamemanagers: "+engineVersion+
                        "\nتوقيع IL2CPP القياسي: "+(meta!=null&&meta.optBoolean("classic_il2cpp_magic")?"موجود":"غير موجود")+
                        "\nARM64 native code: "+(nativeArm?"نفّذ الاختبار":"لم ينفذ")+
                        "\nVulkan instance: "+(vkReady?"نجح الإنشاء":"لم يثبت")+
                        "\nGPU الأصلي: "+gpuName+
                        "\nGPU clear + readback: "+(gpuWork?"نجحت الكتابة والقراءة":"لم تثبت بعد")+
                        "\nاختبار Vulkan: "+gpuStage+
                        "\nفحص مكتبات Windows: "+importStatus+
                        "\nعدد DLL المستوردة: "+importCount+
                        "\nفهرس Unity الكامل: "+(catalogParsed?"تمت القراءة":"غير مكتمل")+
                        "\nمراجع موارد Windows64: "+windowsReferences+
                        "\nإجمالي مراجع الملفات: "+catalogReferences+
                        "\nمطابقة أسماء الحزم: "+(matchVerified?"مكتملة":"غير مكتملة")+
                        "\nأسماء الحزم المسجلة بالفهرس: "+distinctRefs+
                        "\nملفات موجودة غير مسجلة: "+physicalOnly+
                        "\nمراجع بلا ملف مطابق: "+catalogOnly+
                        "\nمسارات Android الفعلية بالفهرس: "+androidTargetPaths+
                        "\nأسماء ملفات لم تُقبل: "+unsupportedPhysical+
                        "\nمراجع كتالوج ملتبسة: "+ambiguousCatalog+
                        "\nحالة المطابقة: "+sourceAuditStatus+
                        "\nتشغيل PC على ARM64: غير متاح — محرك البورت غير مبني بعد"+
                        "\nاضغط حفظ التقرير وارفعة بالمحادثة حتى نفحص نسخة لعبتك الفعلية.");
                });
            }catch(Exception e) {
                main.post(() -> {
                    scanning=false;rescan.setEnabled(tree!=null);aotSource.setEnabled(tree!=null);
                    status.setText("فشل الفحص");
                    details.setText(e.getClass().getSimpleName()+": "+e.getMessage()+
                        "\nجرّب اختيار المجلد الرئيسي الذي يحتوي CarX Street.exe");
                });
            }
        });
    }
    private void requestAotCodeExport() {
        if(tree==null || scanning) {
            Toast.makeText(this,"اختار مجلد CarX Street أولاً",Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/zip");
        i.putExtra(Intent.EXTRA_TITLE,"CarX_GameAssembly_AOT_ExecutableGaps_v1.4.zip");
        startActivityForResult(i,EXPORT_AOT_CODE);
    }
    private void exportAotCode(Uri output) {
        if(tree==null || scanning)return;
        scanning=true;
        rescan.setEnabled(false);
        aotSource.setEnabled(false);
        status.setText("جاري استخراج كود الفجوات بين المقاطع الأصلية...");
        Uri savedTree=tree;
        worker.execute(() -> {
            try(OutputStream out=getContentResolver().openOutputStream(output,"w")) {
                if(out==null)throw new IllegalStateException("تعذر فتح مكان حفظ ZIP");
                GameAssemblyCodeBridge.ExportStats result=
                        GameAssemblyCodeBridge.exportSamples(
                                getContentResolver(),savedTree,out);
                main.post(() -> {
                    scanning=false;
                    rescan.setEnabled(true);
                    aotSource.setEnabled(true);
                    status.setText("نجح استخراج كود CarX والفجوات التنفيذية");
                    details.setText("دوال PE x86-64 الأصلية المؤهلة: "+
                            result.eligibleExecutableFunctions+
                            "\nعينات الدوال المصدّرة: "+result.chosenActualFunctionSamples+
                            "\nبايتات الكود المصدرة: "+result.bytesExported+
                            "\nسجلات UNWIND_INFO الأصلية: "+result.uniqueUnwindRecordsExported+
                            "\nعناوين UNWIND متنوعة: "+result.chosenActualFunctionSamples+
                            "\nروابط CHAININFO: "+result.chainedUnwindReferences+
                            "\nمقاطع كود الدوال الأم: "+result.uniqueParentCodeFragments+
                            "\nحجم كود الأم بالبايت: "+result.parentCodeBytesExported+
                            "\nفجوات كود PE المستخرجة: "+result.uniqueExecutableGapCodeRegions+
                            "\nبايتات كود الفجوات: "+result.executableGapCodeBytes+
                            "\nفجوات غير متاحة: "+result.executableGapCodeMissing+
                            "\nمقاطع أم لم تُستخرج: "+result.parentCodeReferencesNotExtracted+
                            "\nسلاسل UNWIND المكتملة: "+result.functionsWithCompleteUnwindChain+
                            "\nسلاسل تحتاج مراجعة: "+result.functionsWithUnwindReadIssues+
                            "\nالنتيجة: ZIP يحتوي code/ وunwind/ وparents/ وgaps/ وmanifest.json"+
                            "\nالحزمة تشمل كود الفجوات الأصلي من GameAssembly؛ مو تشغيل اللعبة. ارفعها حتى نجرب CFG متعدد المقاطع ونتحقق من مسار الدالة.");
                });
            }catch(Exception error) {
                main.post(() -> {
                    scanning=false;
                    rescan.setEnabled(true);
                    aotSource.setEnabled(true);
                    status.setText("فشل استخراج الدوال: "+
                            error.getClass().getSimpleName());
                    details.setText(error.getMessage()==null?
                            "راجع صلاحية المجلد وملف GameAssembly.dll":
                            error.getMessage());
                });
            }
        });
    }

    private void copyReport() {
        if(lastReport==null)return;
        ClipboardManager c=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
        if(c!=null)c.setPrimaryClip(ClipData.newPlainText("CarX PC Port Diagnostic",lastReport));
        Toast.makeText(this,"اننسخ تقرير الفحص",Toast.LENGTH_SHORT).show();
    }
    private void saveReport() {
        if(lastReport==null)return;
        Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/json");
        i.putExtra(Intent.EXTRA_TITLE,"CarX_Street_PC_Port_Report_v0.9.json");
        startActivityForResult(i,EXPORT_JSON);
    }
    @Override protected void onDestroy() {
        abort.set(true);
        worker.shutdownNow();
        super.onDestroy();
    }
}
