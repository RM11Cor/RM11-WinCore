package com.rm11.autocore.runtime;

import com.rm11.autocore.PeImportReader;
import com.rm11.autocore.PeVersionReader;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * Read-only, per-EXE compatibility preflight, NOT a claim that graphics work.
 * All recommendations are evidence-based suggestions, never silent DLL/registry
 * changes. CarX's existing proven-enough dedicated launch path is preserved.
 */
public final class GameCompatibilityV49064 {
    private GameCompatibilityV49064() {}
    public static final String VERSION="R4_V49064_GAME_PROFILE";
    public static final class Result {
        public final String title,api,engine,architecture,launchRole,recommendation,confidence;
        public final boolean isCarx,hasAntiCheat,requiresDx12,hasLocalD3d,hasImportTable;
        Result(String title,String api,String engine,String arch,String role,
               String advice,String confidence,boolean carx,boolean anticheat,
               boolean dx12,boolean local,boolean hasImports) {
            this.title=title;this.api=api;this.engine=engine;this.architecture=arch;
            this.launchRole=role;this.recommendation=advice;this.confidence=confidence;
            this.isCarx=carx;this.hasAntiCheat=anticheat;this.requiresDx12=dx12;
            this.hasLocalD3d=local;this.hasImportTable=hasImports;
        }
        public String toJournal(){
            return VERSION+"\n"
                +"TITLE="+title+"\nAPI="+api+"\nARCH="+architecture+"\nENGINE="+engine
                +"\nROLE="+launchRole+"\nANTI_CHEAT_PRESENT="+hasAntiCheat
                +"\nLOCAL_D3D_DLLS="+hasLocalD3d
                +"\nREQUIRES_DX12_EVIDENCE="+requiresDx12
                +"\nIMPORT_TABLE_PRESENT="+hasImportTable
                +"\nCONFIDENCE="+confidence+"\nSUGGESTION="+recommendation
                +"\nCONFIGURATION_CHANGED=false"
                +"\nWINE_HID_WINEBUS_UNCHANGED=true"
                +"\nGAME_RENDERING_NOT_PROVEN=true";
        }
        public JSONObject toJson(){
            JSONObject j=new JSONObject();
            try{
                j.put("title",title);j.put("api",api);j.put("engine",engine);
                j.put("architecture",architecture);j.put("role",launchRole);
                j.put("recommendation",recommendation);j.put("confidence",confidence);
                j.put("hasAntiCheat",hasAntiCheat);j.put("requiresDx12",requiresDx12);
                j.put("hasLocalD3d",hasLocalD3d);
                j.put("profile",isCarx?"CARX_EXISTING_DEDICATED":"COMMON_SAFE_BASELINE");
            }catch(Exception ignored){}
            return j;
        }
    }
    private static boolean dirHas(File dir,String name) {
        if(dir==null||!dir.isDirectory())return false;
        // Exact names only; avoid walking gigabytes of game content.
        return new File(dir,name).isFile();
    }
    private static String suggestRealExe(File selected){
        File parent=selected.getParentFile();
        if(parent==null)return null;
        File root=parent;
        for(int i=0;i<3&&root!=null;i++,root=root.getParentFile()){
            for(String relative:new String[]{
                  "bin/x64/Cyberpunk2077.exe",
                  "bin/x64/witcher3.exe",
                  "bin/x64_dx12/witcher3.exe",
                  "Game/Binaries/Win64/Game-Win64-Shipping.exe"}) {
                File actual=new File(root,relative);
                if(actual.isFile())return actual.getAbsolutePath();
            }
        }
        return null;
    }
    public static Result inspect(Path exe) {
        if(exe==null)return new Result("غير معروف","غير محدد","غير محدد",
            "غير محدد","INVALID_PATH","مسار اللعبة غير محدد.","منخفض",false,false,
            false,false,false);
        File file=exe.toFile(),dir=file.getParentFile();
        String name=file.getName(),lower=name.toLowerCase(Locale.ROOT);
        String title=name.replaceAll("(?i)\\.exe$","").replace('_',' ');
        String arch="غير محدد",api="غير محدد",engine="غير محدد";
        List<String> imports=java.util.Collections.emptyList();
        boolean table=false;
        if(file.isFile()){
            try(FileInputStream input=new FileInputStream(file);
                FileChannel ch=input.getChannel()){
                PeImportReader.Info info=PeImportReader.read(ch);
                arch=info.architecture;
                imports=info.importedDlls;table=info.importTablePresent;
                try{
                    PeVersionReader.Info v=PeVersionReader.read(ch);
                    if(v.productName!=null&&!v.productName.trim().isEmpty())
                        title=v.productName.trim();
                }catch(Exception ignored){}
            }catch(Exception ignored){}
        }
        boolean d12=false,d11=false,d9=false,vk=false,gl=false,anti=false;
        for(String imported:imports){
            String p=imported.toLowerCase(Locale.ROOT);
            if(p.equals("d3d12.dll"))d12=true;
            if(p.equals("d3d11.dll")||p.equals("dxgi.dll"))d11=true;
            if(p.equals("d3d9.dll")||p.equals("d3d10core.dll"))d9=true;
            if(p.equals("vulkan-1.dll"))vk=true;
            if(p.equals("opengl32.dll"))gl=true;
            if(p.contains("easyanticheat")||p.contains("battleye")
                ||p.contains("bedaisy"))anti=true;
        }
        boolean local=dirHas(dir,"d3d12.dll")||dirHas(dir,"d3d11.dll")
            ||dirHas(dir,"dxgi.dll")||dirHas(dir,"d3d9.dll");
        boolean anticheat=anti||dirHas(dir,"EasyAntiCheat_EOS_Setup.exe")
            ||dirHas(dir,"EasyAntiCheat_x64.dll")
            ||dirHas(dir,"BEService.exe")||dirHas(dir,"BEService_x64.exe");
        boolean carx=CarXStreetDxvkV49032.isSelectedCarXStreet(exe);
        boolean launcher=lower.contains("launcher")||lower.contains("prelauncher")
            ||lower.equals("steam.exe")||lower.equals("redlauncher.exe");
        if(d12)api="Direct3D 12 (PE imports)";
        else if(d11)api="Direct3D 11 / DXGI (PE imports)";
        else if(d9)api="Direct3D 9/10 (PE imports)";
        else if(vk)api="Vulkan (PE imports)";
        else if(gl)api="OpenGL (PE imports)";
        if(dir!=null) {
            if(dirHas(dir,"UnityPlayer.dll")||dirHas(dir,"GameAssembly.dll"))
                engine="Unity (قرائن ملفات)";
            else if(dirHas(dir,"Engine/Binaries/Win64/UnrealEditor.exe")
                ||dirHas(dir,"Engine/Binaries/Win64/UnrealGame.exe")
                ||lower.contains("win64-shipping"))engine="Unreal Engine (قرائن)";
        }
        String role=launcher?"LAUNCHER_NOT_CONFIRMED_GAME_EXE":"CANDIDATE_GAME_EXE";
        String conf=table?"متوسط - imports لا تكشف التحميل الديناميكي":
            "منخفض - لا يوجد دليل كافٍ من جدول imports";
        String advice;
        if(launcher){
            String candidate=suggestRealExe(file);
            advice=candidate==null?
                "الملف يبدو مشغّل ألعاب، وليس ملف التشغيل الداخلي. ابحث عن EXE الفعلي داخل مجلد اللعبة.":
                "هذا يبدو مشغّلاً؛ جرب ملف اللعبة الفعلي الموجود: "+candidate;
        }else if(anticheat){
            advice="ظهرت قرائن Anti-Cheat؛ لا يمكن ضمان تشغيل لعبة محمية داخل Wine. لا تعطل الحماية أو تتجاوزها. افحص توافق اللعبة والإصدار الرسمي.";
        }else if(carx){
            advice="CarX Street تستخدم مسار DXVK الخاص الموجود مسبقاً. نبقيه كما هو حتى لا نخسر التشغيل الناجح.";
        }else if(d12){
            advice="اللعبة تستورد D3D12. تحتاج تقييم VKD3D-Proton وVulkan/WSI عتادي قبل تفعيل أي مكون. DXVK D3D11 وحده لا يكفي.";
        }else if(d11||d9){
            advice="يوجد دليل Direct3D قديم. نحتاج التحقق من DLL الذي حمّلته Wine فعلياً ومن سجل DXVK، ثم اختيار مسار رسومي خاص لهذه اللعبة.";
        }else{
            advice="الواجهة البرمجية غير مؤكدة؛ افحص سجل Wine وتحميل DLL، وتأكد من اختيار EXE الصحيح قبل تغيير DXVK أو Wine.";
        }
        if(local&&!launcher)advice+=" يوجد DLL رسومي محلي في مجلد EXE؛ قد يغيّر أولوية التحميل.";
        return new Result(title,api,engine,arch,role,advice,conf,carx,anticheat,
                          d12,local,table);
    }
}
