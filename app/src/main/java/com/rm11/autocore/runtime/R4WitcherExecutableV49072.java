package com.rm11.autocore.runtime;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.Locale;

/** Select an installed Witcher 3 DX11 binary over a launcher / DX12 binary.
 * Never mutate, copy, rename or patch the user's games. This policy does
 * not mistake 2026 Remastered DX12-only builds for DirectX 11 compatible. */
public final class R4WitcherExecutableV49072 {
    private R4WitcherExecutableV49072(){}
    public static final String ORIGINAL="ORIGINAL_EXE";
    public static final String CLASSIC_DX11="WITCHER3_CLASSIC_DX11";
    public static final String DX12_ONLY="WITCHER3_DX12_ONLY_REQUIRES_VKD3D";
    public static final class Selection {
        public final File executable;
        public final String status;
        public Selection(File executable,String status){
            this.executable=executable;this.status=status;
        }
        public boolean blocked(){return DX12_ONLY.equals(status);}
    }
    private static boolean valid(File exe) {
        try{return exe!=null && Files.isRegularFile(exe.toPath(),LinkOption.NOFOLLOW_LINKS)
            &&!Files.isSymbolicLink(exe.toPath()) && exe.length()>512;}
        catch(Exception e){return false;}
    }
    /** Works on a parent chosen DX12 EXE, REDlauncher, or classic DX11 exe. */
    public static Selection resolve(File requested) {
        if(requested==null)return new Selection(null,ORIGINAL);
        String name=requested.getName().toLowerCase(Locale.ROOT);
        if(!name.equals("witcher3.exe")&&!name.equals("redlauncher.exe")
                &&!name.equals("redprelauncher.exe"))
            return new Selection(requested,ORIGINAL);
        try{
            File start=requested.getCanonicalFile();
            File dir=start.getParentFile();
            for(int depth=0;dir!=null&&depth<6;depth++,dir=dir.getParentFile()){
                File classic=new File(dir,"bin/x64/witcher3.exe");
                File modern=new File(dir,"bin/x64_dx12/witcher3.exe");
                boolean classicOk=valid(classic);
                boolean modernOk=valid(modern);
                if(classicOk)return new Selection(classic.getCanonicalFile(),CLASSIC_DX11);
                if(modernOk)return new Selection(modern.getCanonicalFile(),DX12_ONLY);
            }
            if(name.equals("witcher3.exe")&&start.getParentFile()!=null
                &&"x64_dx12".equalsIgnoreCase(start.getParentFile().getName()))
                return new Selection(start,DX12_ONLY);
        }catch(Exception ignored){}
        return new Selection(requested,ORIGINAL);
    }
    public static boolean classicDx11(File exe) {
        if(exe==null||!"witcher3.exe".equalsIgnoreCase(exe.getName()))return false;
        File parent=exe.getParentFile();
        return parent!=null && "x64".equalsIgnoreCase(parent.getName())
            &&parent.getParentFile()!=null
            &&"bin".equalsIgnoreCase(parent.getParentFile().getName())
            &&valid(exe);
    }
}
