package com.rm11.autocore.engine;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

/**
 * Native-process ownership, pipe-drain, shutdown, force-kill and isolation
 * contract. Tests run with a JVM child, never with a user's Wine/game data.
 */
public final class EngineOwnedProcessSessionSelfTest {
    private static int asserts=0;
    private static void check(boolean value,String label){
        if(!value)throw new AssertionError(label);
        asserts++;
    }
    private static ProcessBuilder worker(String mode){
        String java=Path.of(System.getProperty("java.home"),"bin","java").toString();
        return new ProcessBuilder(java,"-cp",System.getProperty("java.class.path"),
                EngineOwnedProcessSessionSelfTest.Worker.class.getName(),mode);
    }
    public static final class Worker{
        public static void main(String[] args)throws Exception{
            if("done".equals(args[0])){
                System.out.println("OWNED_PROCESS_STARTED");
                return;
            }
            if("fill".equals(args[0])){
                for(int i=0;i<9000;i++)
                    System.out.println("RM11_ENGINE_LOG_SAMPLE_"+i);
                return;
            }
            System.out.println("OWNED_LONG_RUNNING");
            System.out.flush();
            Thread.sleep(30000);
        }
    }
    private static void waitForTail(EngineOwnedProcessSession.OwnedProcess p,
            String marker)throws Exception{
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(System.nanoTime()<until&&!p.outputTail().contains(marker)){
            Thread.sleep(10);
        }
        check(p.outputTail().contains(marker),"missing "+marker);
    }
    public static void main(String[] args)throws Exception{
        try(EngineOwnedProcessSession session=new EngineOwnedProcessSession()){
            var completed=session.startHostTestProcess(worker("done"));
            waitForTail(completed,"OWNED_PROCESS_STARTED");
            check(session.state()==EngineOwnedProcessSession.State.ACTIVE,"active");
            var flood=session.startHostTestProcess(worker("fill"));
            long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
            while(flood.alive() && System.nanoTime()<until)Thread.sleep(25);
            check(!flood.alive(),"pipe drain prevents stdout backpressure deadlock");
            check(flood.outputTail().length()<=32768,"bounded log storage");
            check(flood.outputTail().contains("RM11_ENGINE_LOG_SAMPLE_8999"),
                    "tail retains latest stdout");
            check(!flood.outputTail().contains("RM11_ENGINE_LOG_SAMPLE_0\n"),
                    "tail discards ancient stdout");
            check(session.launchedCount()==2,"only owned processes registered");
        }
        EngineOwnedProcessSession session=new EngineOwnedProcessSession();
        var childA=session.startHostTestProcess(worker("sleep"));
        var childB=session.startHostTestProcess(worker("sleep"));
        waitForTail(childA,"OWNED_LONG_RUNNING");
        waitForTail(childB,"OWNED_LONG_RUNNING");
        Process unrelated=worker("sleep").start();
        try{
            long start=System.nanoTime();
            session.stopAll(800);
            long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start);
            check(elapsed<7500,"bounded shutdown: "+elapsed+"ms");
            check(!childA.alive()&&!childB.alive(),"both owned children reaped");
            check(unrelated.isAlive(),"unrelated process must remain alive");
            check(session.state()==EngineOwnedProcessSession.State.CLOSED,"closed");
            session.close();
            check(session.launchedCount()==2,"no new children after close");
            try{
                session.startHostTestProcess(worker("done"));
                throw new AssertionError("closed session illegally launched child");
            }catch(IOException expected){
                check(expected.getMessage().contains("ENGINE_SESSION_NOT_ACTIVE"),
                    "closed session rejects launch");
            }
        }finally{
            unrelated.destroyForcibly();
            unrelated.waitFor(2,TimeUnit.SECONDS);
            session.close();
        }
        System.out.println("RM11_ENGINE_PROCESS_SUPERVISOR_PASS checks="+asserts);
    }
}
