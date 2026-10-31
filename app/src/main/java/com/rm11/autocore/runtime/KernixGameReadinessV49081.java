package com.rm11.autocore.runtime;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;
import org.json.JSONObject;

/**
 * KERNIX read-only game-source readiness.
 *
 * Local path and known neighboring asset checks only; not a hardware,
 * DRM, game-launch success or Wine compatibility guarantee. Unknown titles
 * are never rejected on uncertain hints. No filesystem tree walks, writes
 * or bundled game copies.
 */
public final class KernixGameReadinessV49081 {
    private KernixGameReadinessV49081(){}
    public static final String SOURCE_READY="SOURCE_ACCESSIBLE";
    public static final String SOURCE_MISSING="EXE_MISSING_OR_UNREADABLE";
    public static final String ROOT_MISSING="GAME_DIRECTORY_UNREADABLE";
    public static final String FILE_TINY="EXE_TOO_SMALL";
    public static final String ASSET_WARNING="ASSETS_NEED_REVIEW";
    public static final class Result {
        public final String status,detail,kind;
        public final boolean canAttempt,sourceReadable,assetWarning;
        public final int siblingFiles;
        Result(String status,String detail,String kind,boolean attempt,
               boolean dirRead,boolean warn,int siblings){
            this.status=status;this.detail=detail;this.kind=kind;
            canAttempt=attempt;sourceReadable=dirRead;assetWarning=warn;
            siblingFiles=siblings;
        }
        /** The UI never receives the user's absolute game path. */
        public JSONObject toJson(){
            JSONObject j=new JSONObject();
            try{
                j.put("status",status);j.put("detail",detail);
                j.put("kind",kind);j.put("canAttempt",canAttempt);
                j.put("sourceReadable",sourceReadable);
                j.put("assetWarning",assetWarning);
                j.put("siblingsScanned",siblingFiles);
                j.put("renderVerified",false);
            }catch(Exception ignored){}
            return j;
        }
        public String evidence(){
            return "KERNIX_GAME_SOURCE_STATE="+status+"\n"
                +"KERNIX_GAME_KIND="+kind+"\n"
                +"KERNIX_GAME_FOLDER_READABLE="+sourceReadable+"\n"
                +"KERNIX_GAME_ASSET_WARNING="+assetWarning+"\n"
                +"KERNIX_SIBLINGS_UP_TO_256="+siblingFiles+"\n"
                +"KERNIX_ORIGINAL_GAME_FILES_CHANGED=false\n"
                +"KERNIX_RENDERING_UNVERIFIED=true";
        }
    }
    private static Result fail(String why,String description){
        return new Result(why,description,"UNKNOWN",false,false,false,0);
    }
    private static boolean file(Path path){
        return path!=null && Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)
            &&Files.isReadable(path);
    }
    private static boolean directory(Path path){
        return path!=null && Files.isDirectory(path)
            &&Files.isReadable(path);
    }
    private static int boundedSiblings(Path directory){
        int count=0;
        try(java.nio.file.DirectoryStream<Path> children=Files.newDirectoryStream(directory)){
            for(Path ignored:children){if(++count>=256)break;}
        }catch(Exception ignored){}
        return count;
    }
    public static Result inspect(Path original){
        if(original==null)return fail(SOURCE_MISSING,"اختار ملف EXE أولاً");
        try{
            if(!file(original))return fail(SOURCE_MISSING,
                "ملف اللعبة غير موجود أو غير قابل للقراءة");
            if(Files.size(original)<=64)
                return fail(FILE_TINY,"ملف EXE صغير جداً أو غير مكتمل");
            Path folder=original.getParent();
            if(!directory(folder))
                return fail(ROOT_MISSING,"مجلد اللعبة الأصلي غير قابل للقراءة");
            String name=original.getFileName().toString();
            String lower=name.toLowerCase(Locale.ROOT);
            int siblingCount=boundedSiblings(folder);
            String kind="GENERIC_WINDOWS_EXE",advice="ملف EXE ومجلده الأصلي قابلان للقراءة";
            boolean warning=false;
            if(file(folder.resolve("UnityPlayer.dll"))){
                kind="UNITY_LAYOUT";
                String base=name.replaceFirst("(?i)\\.exe$","");
                boolean data=directory(folder.resolve(base+"_Data"));
                if(!data){
                    warning=true;
                    advice="UnityPlayer.dll موجود لكن مجلد "+base
                        +"_Data غير ظاهر بجانب EXE. تحقق من اكتمال ملفات اللعبة.";
                }else advice="ملفات Unity الأساسية في نفس مجلد EXE";
            }
            if(lower.equals("witcher3.exe") && folder.getFileName()!=null
                &&folder.getFileName().toString().equalsIgnoreCase("x64_dx12")){
                kind="WITCHER3_DX12_LAYOUT";
                Path bin=folder.getParent();
                Path root=bin==null?null:bin.getParent();
                boolean content=directory(root==null?null:root.resolve("content"));
                if(!content){
                    warning=true;
                    advice="مجلد content غير موجود بالنسبة لمسار bin/x64_dx12؛ "
                        +"تشغيل DirectX 12 قد يتوقف بسبب نقص ملفات اللعبة.";
                }else advice="مسار content النسبي من x64_dx12 موجود؛ "
                    +"هذا لا يثبت جاهزية VKD3D أو Vulkan.";
            }
            return new Result(warning?ASSET_WARNING:SOURCE_READY,advice,kind,
                true,true,warning,siblingCount);
        }catch(IOException|SecurityException e){
            return fail(SOURCE_MISSING,"تعذر فحص ملف اللعبة: "+
                e.getClass().getSimpleName());
        }
    }
}
