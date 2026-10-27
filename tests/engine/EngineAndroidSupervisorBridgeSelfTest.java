package com.rm11.autocore.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Host proof of Java -> signed-hash-native-supervisor -> native child handoff.
 *
 * Uses a harmless shell stub instead of actual Wine; intentionally does NOT
 * claim Android Bionic startup or Windows game rendering.
 */
public final class EngineAndroidSupervisorBridgeSelfTest {
    private static int checks=0;
    private static void require(boolean condition,String message){
        if(!condition)throw new AssertionError(message);
        checks++;
    }
    private static void mustReject(EngineOwnedProcessSession session,Path root,
                                   Path work,String wineHash,String supervisorHash,
                                   java.util.Map<String,String> env,String reason)
            throws IOException{
        try{
            session.startSupervisedWine(root,List.of("-test"),work,env,
                    supervisorHash,wineHash);
            throw new AssertionError("UNEXPECTED_WINE_LAUNCH_FOR_"+reason);
        }catch(IOException e){
            require(e.getMessage().contains(reason),
                    "wrong reject reason: "+e.getMessage());
        }
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=1)throw new IllegalArgumentException("HOST_NATIVE_BIN_ARG");
        Path temporary=Files.createTempDirectory("rm11-owner-chain-");
        try{
            Path root=Files.createDirectory(temporary.resolve("apk-native-root"));
            Path supervisor=root.resolve("librm11_engine_supervisor.so");
            Path wine=root.resolve("libwineprobe.so");
            Files.copy(Path.of(args[0]),supervisor,StandardCopyOption.REPLACE_EXISTING);
            Files.writeString(wine,"#!/bin/sh\necho RM11_WINE_SIMULATED_STUB\nexit 0\n");
            require(supervisor.toFile().setExecutable(true),"host supervisor executable");
            require(wine.toFile().setExecutable(true),"host wine stub executable");
            String supervisorHash=EngineDataStager.sha256(supervisor);
            String wineHash=EngineDataStager.sha256(wine);
            try(EngineOwnedProcessSession owner=new EngineOwnedProcessSession()){
                EngineOwnedProcessSession.OwnedProcess child=
                        owner.startSupervisedWine(root,List.of("-test"),
                            temporary,Collections.emptyMap(),
                            supervisorHash,wineHash);
                long stop=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
                while(child.alive()&&System.nanoTime()<stop)
                    Thread.sleep(10);
                require(!child.alive(),"signed native supervisor exits and reaps child");
                require(Integer.valueOf(0).equals(child.exitCodeIfFinished()),
                        "native supervisor propagated Wine stub success");
                require(child.outputTail().contains("RM11_WINE_SIMULATED_STUB"),
                        "Java owner drains native Wine child output");

                mustReject(owner,root,temporary,"0".repeat(64),supervisorHash,
                        Collections.emptyMap(),"ENGINE_WINE_LOADER_HASH_MISMATCH");
                mustReject(owner,root,temporary,wineHash,"0".repeat(64),
                        Collections.emptyMap(),"ENGINE_NATIVE_ENTRYPOINT_HASH_MISMATCH");
                HashMap<String,String> wrong=new HashMap<>();
                wrong.put("RM11_ENGINE_APK_LIB_DIR","/tmp/attacker");
                mustReject(owner,root,temporary,wineHash,supervisorHash,
                        wrong,"ENGINE_NATIVE_DIR_OVERRIDE_REJECTED");
                require(owner.launchedCount()==1,
                        "failed hash/dir gates spawn no extra guest processes");
            }
            System.out.println("RM11_ENGINE_JAVA_NATIVE_BRIDGE_PASS checks="+checks);
        }finally{
            try(java.util.stream.Stream<Path> paths=Files.walk(temporary)){
                for(Path p:(Iterable<Path>)paths.sorted(
                        java.util.Comparator.reverseOrder())::iterator)
                    Files.deleteIfExists(p);
            }
        }
    }
}
