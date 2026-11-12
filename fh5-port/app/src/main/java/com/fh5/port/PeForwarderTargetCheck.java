package com.fh5.port;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * P4.0: one-hop, read-only verification of forwarded export targets.
 * A matching PE64 export is NOT proof that Windows or the game can call it.
 * No DLL is mapped, loaded, resolved in a running process, or executed.
 */
public final class PeForwarderTargetCheck {
    private PeForwarderTargetCheck() {}
    public static final String DIRECT="TARGET_PE64_EXPORT_PRESENT";
    public static final String CHAIN="TARGET_POINTS_TO_ANOTHER_FORWARDER";
    public static final String MISSING="TARGET_EXPORT_ABSENT";
    public static final String NO_FILE="TARGET_DLL_NOT_BESIDE_EXE";
    public static final String INCOMPLETE="TARGET_PE_EXPORT_INDEX_UNAVAILABLE";
    public static final String BAD_TARGET="FORWARDER_TARGET_METADATA_INVALID";
    public static final String MAX_HOP_REACHED="ONLY_FIRST_FORWARDER_HOP_CHECKED";
    public static final int MAX_TARGETS=16;

    public static String candidateName(String module) {
        if(module==null || !module.matches("[A-Za-z0-9_.-]{1,120}"))
            throw new IllegalArgumentException("pe_target_module_invalid");
        String lower=module.toLowerCase(Locale.ROOT);
        String dll=lower.endsWith(".dll")?lower:lower+".dll";
        if(!dll.matches("[a-z0-9_.-]{1,128}\\.dll"))
            throw new IllegalArgumentException("pe_target_dll_invalid");
        return dll;
    }
    public static final class Result {
        public final String status,dllName,exportNameOrOrdinal;
        public final boolean targetFileVisible,actualGameExecuted=false,
            abiVerified=false,iatWritten=false;
        Result(String state,String file,String symbol,boolean visible) {
            status=state;dllName=file;exportNameOrOrdinal=symbol;
            targetFileVisible=visible;
        }
    }
    public static Result assess(PeForwarderProbe.Target target,
          Map<String,PeExportIndex.Result> indexes,Set<String> presentFiles) {
        if(target==null||indexes==null||presentFiles==null)
            throw new IllegalArgumentException("pe_target_missing_input");
        if(!"FORWARDER_TARGET_DECODED".equals(target.status))
            return new Result(BAD_TARGET,"","",false);
        final String file;
        try {file=candidateName(target.targetModule);}
        catch(IllegalArgumentException ex){
            return new Result(BAD_TARGET,"","",false);
        }
        if(!presentFiles.contains(file))
            return new Result(NO_FILE,file,target.targetFunction,false);
        PeExportIndex.Result exports=indexes.get(file);
        if(exports==null || !exports.complete)
            return new Result(INCOMPLETE,file,target.targetFunction,true);
        String status;
        if(target.ordinal) {
            if(!target.targetFunction.matches("#[0-9]{1,5}"))
                return new Result(BAD_TARGET,file,"",true);
            int ordinal;
            try {ordinal=Integer.parseInt(target.targetFunction.substring(1));}
            catch(NumberFormatException e) {
                return new Result(BAD_TARGET,file,"",true);
            }
            status=exports.lookupOrdinal(ordinal);
        } else {
            status=exports.lookupName(target.targetFunction);
        }
        if("DIRECT_EXPORT_PRESENT".equals(status))
            return new Result(DIRECT,file,target.targetFunction,true);
        if("FORWARDED_EXPORT".equals(status))
            return new Result(CHAIN,file,target.targetFunction,true);
        if("EXPORT_INDEX_INCOMPLETE".equals(status))
            return new Result(INCOMPLETE,file,target.targetFunction,true);
        return new Result(MISSING,file,target.targetFunction,true);
    }
}
