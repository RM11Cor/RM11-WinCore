package com.rm11.autocore.runtime;

/**
 * Bounded read-only Wine startup evidence. Unlike a rolling stderr tail,
 * keeps the first startup lines even after a long-running game fills the pipe.
 * Does not infer that Process.isAlive() proves the selected PE loaded.
 */
public final class WineGameStartupEvidenceV486 {
    private static final int LINE_MAX=480;
    private static final int FIRST_MAX=2600;
    private static final int TAIL_MAX=3100;
    private final String gameFile;
    private final StringBuilder pending=new StringBuilder();
    private final StringBuilder beginning=new StringBuilder();
    private String tail="";
    private int lines;
    private boolean freetypeMissing;
    private boolean gnutlsMissing;
    private boolean peExeMentioned;
    private boolean processStartSeen;
    private boolean moduleLoadSeen;
    private boolean wineD3dObserved;
    private boolean winebootFailure;
    private boolean loaderHandoff;
    private boolean vulkanStageReached;
    private boolean droppedLongLine;
    private long totalChars;

    public WineGameStartupEvidenceV486(String selectedFile) {
        gameFile=selectedFile==null?"":selectedFile;
    }
    public synchronized void accept(String chunk) {
        if(chunk==null||chunk.isEmpty())return;
        totalChars+=chunk.length();
        for(int i=0;i<chunk.length();i++){
            char c=chunk.charAt(i);
            if(c=='\n'){
                consumeLine(pending.toString());
                pending.setLength(0);
            }else if(pending.length()<LINE_MAX){
                pending.append(c);
            }else droppedLongLine=true;
        }
    }
    private void consumeLine(String line){
        lines++;
        if(beginning.length()<FIRST_MAX) {
            int free=FIRST_MAX-beginning.length();
            String entry=line+"\n";
            beginning.append(entry,0,Math.min(free,entry.length()));
        }
        tail=WineGameOutputTail.append(tail,line+"\n");
        if(tail.length()>TAIL_MAX)
            tail=tail.substring(tail.length()-TAIL_MAX);
        if(line.contains("Wine cannot find the FreeType font library"))
            freetypeMissing=true;
        if(line.contains("gnutls_process_attach failed to load libgnutls"))
            gnutlsMissing=true;
        if(line.contains("run_wineboot failed")||line.contains("wineboot")&&line.contains("failed to start"))
            winebootFailure=true;
        if(line.contains("RM11_WINE_ENTRY_FOUND"))
            loaderHandoff=true;
        if(line.contains("CreateProcessInternalW")||line.contains("NtCreateUserProcess"))
            processStartSeen=true;
        if(line.contains("Loaded module")||line.contains("Loaded ")&&line.contains(".dll"))
            moduleLoadSeen=true;
        if(line.contains("wined3d")||line.contains("D3D11"))
            wineD3dObserved=true;
        if(line.contains("libvulkan")||line.contains("RM11_V479_PRIVATE_MESA"))
            vulkanStageReached=true;
        if(!gameFile.isEmpty()&&line.toLowerCase(java.util.Locale.ROOT)
                .contains(gameFile.toLowerCase(java.util.Locale.ROOT)))
            peExeMentioned=true;
    }
    public synchronized String snapshot() {
        return "RM11_V486_SELECTED_GAME="+gameFile+"\n"
            +"RM11_V486_WINE_LOADER_HANDOFF="+loaderHandoff+"\n"
            +"RM11_V486_WINE_PROCESS_CREATE_TRACE="+processStartSeen+"\n"
            +"RM11_V486_SELECTED_PE_MENTIONED_IN_TRACE="+peExeMentioned+"\n"
            +"RM11_V486_PE_DLL_MODULE_LOAD_TRACE="+moduleLoadSeen+"\n"
            +"RM11_V486_FREETYPE_MISSING_WARNING="+freetypeMissing+"\n"
            +"RM11_V486_GNUTLS_MISSING_WARNING="+gnutlsMissing+"\n"
            +"RM11_V486_WINEBOOT_LAUNCH_FAILURE_IN_GAME_LOG="+winebootFailure+"\n"
            +"RM11_V486_WINED3D_SIGNAL="+wineD3dObserved+"\n"
            +"RM11_V486_VULKAN_SIGNAL="+vulkanStageReached+"\n"
            +"RM11_V486_GAME_STANDARD_OUTPUT_LINES="+lines+"\n"
            +"RM11_V486_GAME_STANDARD_OUTPUT_CHARS="+totalChars+"\n"
            +"RM11_V486_LONG_LINE_TRUNCATED="+droppedLongLine+"\n"
            +"RM11_V486_SELECTED_PE_EXECUTING=UNVERIFIED\n"
            +"RM11_V486_FIRST_WINE_LINES:\n"+beginning+"\n"
            +"RM11_V486_LAST_WINE_LINES:\n"+tail+"\n";
    }
}
