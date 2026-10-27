package engine;

import com.rm11.autocore.engine.EngineHardwareWsiPolicy;
import java.io.IOException;
import java.util.Map;

public final class EngineHardwareWsiPolicySelfTest {
    private static int checks;
    private static void check(boolean yes){if(!yes)throw new AssertionError();checks++;}
    private static void deny(Map<String,String> env,String code)throws IOException {
        try{
            EngineHardwareWsiPolicy.requireNoSoftwareWsi(env);
            throw new AssertionError("unsafe WSI allowed");
        }catch(IOException expected){
            check(expected.getMessage().contains(code));
        }
    }
    public static void main(String[] args)throws Exception{
        deny(Map.of("MESA_VK_WSI_DEBUG","sw"),"SOFTWARE_WSI");
        deny(Map.of("MESA_VK_WSI_DEBUG","SW"),"SOFTWARE_WSI");
        deny(Map.of("MESA_VK_WSI_DEBUG","foo,sw"),"SOFTWARE_WSI");
        deny(Map.of("RM11_V479_PRIVATE_VULKAN_GAME","1"),
                "LEGACY_SOFTWARE_VULKAN");
        deny(null,"GRAPHICS_ENV_MISSING");
        EngineHardwareWsiPolicy.requireNoSoftwareWsi(Map.of("DISPLAY","127.0.0.1:2"));
        check(true);
        EngineHardwareWsiPolicy.requireNoSoftwareWsi(Map.of("MESA_VK_WSI_DEBUG",""));
        check(true);
        System.out.println("RM11_ENGINE_HARDWARE_WSI_POLICY_PASS checks="+checks);
    }
}
