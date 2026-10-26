package com.rm11.autocore.runtime;

/**
 * Read-only X11 window-count observation for a selected Windows EXE.
 * QueryTree/GetWindowAttributes cannot identify the owner process of an X11
 * window, and a running Wine loader alone is not proof of GUI compatibility.
 * Never claim that a window is associated with the selected executable.
 */
public final class NovaExeWindowEvidence {
    private NovaExeWindowEvidence(){}

    private static int count(String report,String name){
        if(report==null || !report.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK"))
            return -1;
        String key=name+"=";
        for(String line:report.split("\n")){
            if(!line.startsWith(key))continue;
            try{
                int value=Integer.parseInt(line.substring(key.length()).trim());
                return value>=0 ? value:-1;
            }catch(NumberFormatException ignored){return -1;}
        }
        return -1;
    }

    public static String compare(String baseline,String after){
        int beforeView=count(baseline,"x11_children_viewable");
        int afterView=count(after,"x11_children_viewable");
        int beforeRoot=count(baseline,"x11_root_children");
        int afterRoot=count(after,"x11_root_children");
        int beforeErrors=count(baseline,"x11_attribute_errors");
        int afterErrors=count(after,"x11_attribute_errors");
        boolean capped=(baseline!=null&&baseline.contains("x11_children_capped=true"))
                ||(after!=null&&after.contains("x11_children_capped=true"));
        boolean valid=beforeView>=0&&afterView>=0&&beforeRoot>=0&&afterRoot>=0
                &&beforeErrors==0&&afterErrors==0&&!capped;
        String signal=!valid?"INDETERMINATE_X11_AUDIT":
                afterView>beforeView?"NEW_VIEWABLE_ROOT_WINDOW_OBSERVED":
                "NO_VIEWABLE_ROOT_WINDOW_INCREASE";
        return "RM11_V436_X11_WINDOW_SIGNAL="+signal+"\n"
                +"RM11_V436_ROOT_CHILDREN_BEFORE="+beforeRoot+"\n"
                +"RM11_V436_ROOT_CHILDREN_AFTER="+afterRoot+"\n"
                +"RM11_V436_VIEWABLE_BEFORE="+beforeView+"\n"
                +"RM11_V436_VIEWABLE_AFTER="+afterView+"\n"
                +"RM11_V436_WINDOW_OWNER_NOT_DETERMINED=true\n"
                +"RM11_V436_GAME_COMPATIBILITY_NOT_VERIFIED=true";
    }
}
