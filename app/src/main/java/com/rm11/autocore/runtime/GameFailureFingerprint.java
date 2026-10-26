package com.rm11.autocore.runtime;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Evidence classification only: it never guesses whether fixing a symptom
 * will make a game render. Useful when the Wine x64/ARM64EC launcher exits. */
public final class GameFailureFingerprint {
    private GameFailureFingerprint() {}
    private static final Pattern REJECTED=Pattern.compile(
            "RM11_V459_RELAY_REJECTED_CLIENTS=(\\d+)");
    private static final Pattern RESERVED=Pattern.compile(
            "RM11_V459_RELAY_RESERVED_CLIENTS=(\\d+)");
    private static final Pattern MAXIMUM=Pattern.compile(
            "RM11_V459_RELAY_MAX_CLIENTS=(\\d+)");
    private static int number(Pattern pattern,String source) {
        Matcher m=pattern.matcher(source==null?"":source);
        if(!m.find())return -1;
        try{return Integer.parseInt(m.group(1));}
        catch(NumberFormatException e){return -1;}
    }
    public static String inspect(String output,String relay) {
        String wine=output==null?"":output;
        int max=number(MAXIMUM,relay),reserved=number(RESERVED,relay);
        int rejected=number(REJECTED,relay);
        boolean x11=wine.contains("x11drv: Can't open display");
        boolean seh=wine.contains("Exception frame is not in stack limits")
                || wine.contains("seh:call_seh_handlers invalid frame");
        boolean vulkan=wine.contains("RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS");
        return "RM11_V459_FAILURE_FINGERPRINT\n"
            +"RM11_V459_X11_OPEN_FAILED="+x11+"\n"
            +"RM11_V459_RELAY_CAPACITY="+reserved+"/"+max+"\n"
            +"RM11_V459_RELAY_DENIED="+rejected+"\n"
            +"RM11_V459_RELAY_LIMIT_CAUSED_REJECTION="+(rejected>0)+"\n"
            +"RM11_V459_WINE_SEH_INVALID_STACK="+seh+"\n"
            +"RM11_V459_ANDROID_VULKAN_LOADED="+vulkan+"\n"
            +"RM11_V459_GAME_RENDERED=UNVERIFIED\n";
    }
}
