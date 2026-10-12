#!/usr/bin/env python3
"""V0.9 JDK smoke test of the real stager using tiny test-only Android/JSON stubs.

Checks actual stream-to-private-directory operations; Android APK build remains a
separate GitHub Actions validation. No game engine is downloaded or executed.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / 'app/src/main/java/com/rm11/wincore'

STUBS = {
'android/net/Uri.java': r'''package android.net; public class Uri {public final byte[] data; public Uri(byte[] b){data=b;}}''',
'android/content/ContentResolver.java': r'''package android.content; public class ContentResolver {public java.io.InputStream openInputStream(android.net.Uri uri) {return new java.io.ByteArrayInputStream(uri.data);}}''',
'android/content/Context.java': r'''package android.content; public class Context {private final java.io.File files; public Context(java.io.File dir) {files=dir;} public java.io.File getFilesDir(){return files;} public ContentResolver getContentResolver(){return new ContentResolver();}}''',
'android/os/Build.java': r'''package android.os; public class Build {public static class VERSION {public static final int SDK_INT=36;}}''',
'com/rm11/wincore/RuntimeBootstrap.java': r'''package com.rm11.wincore; public class RuntimeBootstrap {public static boolean correctDevice(){return true;}}''',
'org/json/JSONArray.java': r'''package org.json;
public class JSONArray {
    private final java.util.List<JSONObject> objects;
    JSONArray(String str) {
        objects = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\{[^{}]*\\}").matcher(str);
        while(m.find()) objects.add(new JSONObject(m.group()));
    }
    public int length(){return objects.size();}
    public JSONObject getJSONObject(int i){return objects.get(i);}
}''',
'org/json/JSONObject.java': r'''package org.json;
public class JSONObject {
    private final java.util.Map<String,String> values=new java.util.HashMap<>();
    private final String text;
    public JSONObject(String str){
        text=str;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\\"([a-zA-Z0-9]+)\\\"\\s*:\\s*(?:\\\"([^\\\"]*)\\\"|([0-9]+))").matcher(str);
        while(m.find()) values.put(m.group(1),m.group(2)!=null?m.group(2):m.group(3));
    }
    public int getInt(String key){return Integer.parseInt(values.get(key));}
    public long getLong(String key){return Long.parseLong(values.get(key));}
    public String getString(String key){return values.get(key);}
    public JSONArray getJSONArray(String key){
        int start=text.indexOf('['); int end=text.lastIndexOf(']');
        if(start<0||end<start) throw new IllegalArgumentException("missing array");
        return new JSONArray(text.substring(start+1,end));
    }
}''',
'com/rm11/wincore/StageHostTest.java': r'''package com.rm11.wincore;
import android.content.Context; import android.net.Uri;
import java.io.*; import java.nio.charset.StandardCharsets;
import java.nio.file.*; import java.security.*; import java.util.*; import java.util.zip.*;
public class StageHostTest {
    private static String sha(byte[] bytes) throws Exception {
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out=new StringBuilder();
        for(byte b:hash)out.append(String.format(Locale.US,"%02x",b&255));
        return out.toString();
    }
    private static Uri create(byte[] payload, boolean badHash, String path, boolean missing) throws Exception {
        String hash=badHash?"0".repeat(64):sha(payload);
        String manifest="{\"schema\":1,\"targetModel\":\"NX809J\",\"abi\":\"arm64-v8a\",\"minApi\":36,\"components\":["
            +"{\"id\":\"demo\",\"path\":\""+path+"\",\"bytes\":"+payload.length+",\"sha256\":\""+hash+"\",\"license\":\"CC0-1.0\"}]}";
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(ZipOutputStream zip=new ZipOutputStream(bytes)){
            zip.putNextEntry(new ZipEntry("rm11-engine.json"));zip.write(manifest.getBytes(StandardCharsets.UTF_8));zip.closeEntry();
            if(!missing){zip.putNextEntry(new ZipEntry(path));zip.write(payload);zip.closeEntry();}
        }
        return new Uri(bytes.toByteArray());
    }
    static void check(boolean cond, String message){if(!cond) throw new AssertionError(message);}
    public static void main(String[] args) throws Exception {
        File dir=Files.createTempDirectory("rm11-host-stager-").toFile();
        Context ctx=new Context(dir);
        byte[] data="HARmless inert test only".getBytes(StandardCharsets.UTF_8);
        String pass=EngineBundleStager.stage(ctx,create(data,false,"components/demo.blob",false));
        check(pass.contains("[STAGED]"),"Expected good stage: "+pass);
        File staged=new File(dir,"rm11-engine-staged/demo.blob");
        check(staged.isFile(),"Expected inert blob");
        check(Arrays.equals(Files.readAllBytes(staged.toPath()),data),"Staged bytes differ");
        String bad=EngineBundleStager.stage(ctx,create("corrupt".getBytes(StandardCharsets.UTF_8),true,"components/demo.blob",false));
        check(bad.contains("[FAIL]"),"Expected digest failure");
        check(Arrays.equals(Files.readAllBytes(staged.toPath()),data),"Bad ZIP overwrote good stage");
        String missing=EngineBundleStager.stage(ctx,create(data,false,"components/demo.blob",true));
        check(missing.contains("[FAIL]"),"Expected missing component failure");
        String traverse=EngineBundleStager.stage(ctx,create(data,false,"components/../evil",false));
        check(traverse.contains("[FAIL]"),"Expected traversal rejection");
        check(!new File(dir,"evil").exists(),"Path traversal succeeded");
        check(EngineBundleStager.status(ctx).contains("STAGED DATA"),"State missing");
        System.out.println("PASS: V0.9 real ZIP stream staging, checksum, traversal rejection, rollback and status");
    }
}'''
}


def main():
    with tempfile.TemporaryDirectory(prefix='rm11-stage-host-') as td:
        scratch = Path(td)
        paths = []
        for filename, content in STUBS.items():
            p = scratch / filename
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            paths.append(str(p))
        classes = scratch / 'classes'
        classes.mkdir()
        subprocess.run(['javac', '-encoding', 'UTF-8', '-d', str(classes),
                        str(SOURCES / 'EngineBundleStager.java'), *paths], check=True)
        subprocess.run(['java', '-cp', str(classes), 'com.rm11.wincore.StageHostTest'], check=True)


if __name__ == '__main__':
    main()
