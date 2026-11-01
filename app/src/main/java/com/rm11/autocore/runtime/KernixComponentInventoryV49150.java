package com.rm11.autocore.runtime;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only unified truth source for component presence vs device proof.
 * No downloads, prefix mutations, game file writes or graphics activation.
 */
public final class KernixComponentInventoryV49150 {
    private KernixComponentInventoryV49150() {}

    private static boolean nativeFile(Path file) {
        try { return !Files.isSymbolicLink(file)
            && Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)
            && Files.size(file)>4096; }
        catch(Exception ignored){return false;}
    }
    private static boolean asset(Context ctx,String name) {
        try(InputStream in=ctx.getAssets().open(name)) {
            return in.read()>=0;
        }catch(Exception ignored){return false;}
    }
    private static boolean proof(JSONObject qualification,int index) {
        JSONArray checks=qualification.optJSONArray("checks");
        if(checks==null||index<0||checks.length()!=
                KernixEngineQualificationV49090.REQUIRED.length)return false;
        JSONObject row=checks.optJSONObject(index);
        return row!=null
            &&KernixEngineQualificationV49090.REQUIRED[index]
                .equals(row.optString("stage"))
            &&KernixEngineQualificationV49090.VERIFIED
                .equals(row.optString("state"));
    }
    private static void put(JSONObject out,String id,boolean present,
            boolean qualified,String details) throws Exception {
        JSONObject item=new JSONObject();
        item.put("state",KernixComponentRulesV49150
            .state(present,qualified).name());
        item.put("filesPresent",present);
        item.put("deviceProof",present&&qualified);
        item.put("details",details);
        out.put(id,item);
    }
    private static String state(JSONObject components,String id) {
        JSONObject c=components.optJSONObject(id);
        return c==null?"MISSING":c.optString("state","MISSING");
    }

    public static JSONObject snapshot(Context ctx) {
        JSONObject out=new JSONObject();
        try {
            out.put("schema","kernix.component-freeze.v49150");
            out.put("componentFilesAreNotDeviceProof",true);
            out.put("appNeverModifiesUserGameFiles",true);
            out.put("allGamesGuaranteed",false);
            if(ctx==null)return out;
            Path nativeDir=new File(ctx.getApplicationInfo().nativeLibraryDir).toPath();
            RuntimeLayout legacy=new RuntimeLayout(ctx.getFilesDir().toPath(),nativeDir);
            JSONObject proto=KernixProtonProvisioningV49129.snapshot(ctx);
            JSONObject qual=KernixEngineQualificationV49090.snapshot(ctx);
            boolean packagedProton=proto.optBoolean("assetsInstalled",false);
            boolean nativeGuest=proto.optBoolean("nativeWin64GuestQualified",false);
            boolean x11=nativeFile(nativeDir.resolve("libXlorie.so"))
                &&nativeFile(nativeDir.resolve("libwine_winex11.so"));
            boolean wineLegacy=nativeFile(legacy.nativeWineLauncher)
                &&nativeFile(legacy.nativeWineServer);
            boolean dxvk=R4GameRuntimeConfigV49066.hasApkDxvk(ctx);
            boolean vkd3d=R4Vkd3dV49073.hasBundledProvider(ctx);
            boolean nativeVulkan=nativeFile(nativeDir.resolve("librm11_vkdriver_v473.so"))
                &&nativeFile(nativeDir.resolve("librm11_vkloader_v473.so"));
            boolean framesX11=proof(qual,1);
            boolean gpu=proof(qual,2),wsi=proof(qual,3);
            boolean dxvkFrames=proof(qual,4),dx12Frames=proof(qual,5);
            boolean xinputRead=proof(qual,6);
            JSONObject components=new JSONObject();
            put(components,"PROTON",packagedProton,nativeGuest,
                "Proton 11.0-2 signed ARM64EC+FEX slot; GUI separate");
            put(components,"FEX",packagedProton,nativeGuest,
                "FEX 2610 x64/WoW64 paired to signed Proton slot");
            put(components,"WINE_PREFIX",proto.optBoolean("separateWritablePrefix",false),
                proto.optBoolean("prefixUpdateCompleted",false),
                "Isolated writable prefix; a restart-only receipt is not full initialization");
            put(components,"X11",x11,framesX11,
                "Lorie + Wine X11; actual visible window receipt required");
            put(components,"WINED3D",wineLegacy||packagedProton,false,
                "Wine built-in D3D9/10/11 fallback; OpenGL rendering unproven");
            put(components,"DXVK",dxvk,
                dxvk&&framesX11&&gpu&&wsi&&dxvkFrames,
                "Signed x64 d3d11/dxgi plus GPU, WSI and frame proof");
            put(components,"VKD3D",vkd3d,
                vkd3d&&framesX11&&gpu&&wsi&&dx12Frames,
                "Signed x64 d3d12/d3d12core plus device frame proof");
            put(components,"VULKAN_GPU",nativeVulkan,nativeVulkan&&gpu,
                "Bundled Vulkan driver; no claim it is a selectable Turnip version");
            put(components,"VULKAN_WSI",nativeVulkan,nativeVulkan&&gpu&&wsi,
                "GPU queue and X11 WSI Present must both pass");
            put(components,"TURNIP_ALTERNATES",false,false,
                "Not registered as a verified selectable alternate driver");
            put(components,"XINPUT",packagedProton||wineLegacy,xinputRead,
                "Native Winebus/XInput needs Windows read from real controller");
            put(components,"AUDIO",packagedProton,false,
                "Wine audio UnixLib packaged; Android audio proof not recorded");
            put(components,"NETWORK",packagedProton,false,
                "Wine network APIs packaged; online/auth servers not guaranteed");
            out.put("components",components);
            out.put("win32GuiDeviceQualified",framesX11);
            out.put("nativeVulkanDeviceQualified",nativeVulkan&&gpu&&wsi);
            out.put("gameEngineActivated",proto.optBoolean("gameEngineActivated",false));
            out.put("allCriticalDeviceProofsPassed",qual.optBoolean("complete",false));
        }catch(Exception e){
            try {out.put("inventoryError",e.getClass().getSimpleName());}
            catch(Exception ignored){}
        }
        return out;
    }

    public static String summary(Context ctx,File exe){
        JSONObject root=snapshot(ctx),parts=root.optJSONObject("components");
        if(parts==null)return "KERNIX_COMPONENT_AUDIT_NOT_AVAILABLE";
        StringBuilder s=new StringBuilder("KERNIX — منظومة المكونات الموحدة v49150\n");
        String[][] labels={
            {"PROTON","Proton 11 ARM64EC"},{"FEX","FEX 2610"},
            {"WINE_PREFIX","Wine prefix"},{"X11","X11 / Lorie"},
            {"WINED3D","WineD3D"},{"DXVK","DXVK D3D11"},
            {"VKD3D","VKD3D D3D12"},{"VULKAN_GPU","Vulkan GPU"},
            {"VULKAN_WSI","Vulkan Present"},{"TURNIP_ALTERNATES","Turnip alternatives"},
            {"XINPUT","XInput"},{"AUDIO","Audio"},{"NETWORK","Network"}
        };
        for(String[] row:labels)
            s.append(row[1]).append(": ").append(state(parts,row[0])).append('\n');
        s.append("\nMISSING = غير مسجل؛ PACKAGED_UNVERIFIED = ملفاته موجودة فقط؛ ")
         .append("DEVICE_QUALIFIED = اجتاز فحص الجهاز لهذه الطبقة.\n");
        s.append("نجاح البناء لا يثبت عرض اللعبة أو حماية الشبكة.\n");
        if(exe!=null){
            GameCompatibilityV49064.Result info=
                GameCompatibilityV49064.inspect(exe.toPath());
            boolean gui=root.optBoolean("win32GuiDeviceQualified",false);
            KernixComponentRulesV49150.Plan plan=
                KernixComponentRulesV49150.recommend(
                    info.api,info.hasAntiCheat,gui,
                    !"MISSING".equals(state(parts,"WINED3D")),
                    "DEVICE_QUALIFIED".equals(state(parts,"DXVK")),
                    "DEVICE_QUALIFIED".equals(state(parts,"VKD3D")),
                    root.optBoolean("nativeVulkanDeviceQualified",false));
            s.append("\nاقتراح لهذه اللعبة: ").append(plan.backend)
             .append(" — ").append(plan.reason)
             .append("\nتفضيلات اللعبة المحفوظة لا تتغير تلقائياً.");
        }
        return s.toString();
    }
}
