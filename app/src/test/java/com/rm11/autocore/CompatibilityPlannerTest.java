package com.rm11.autocore;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import static org.junit.Assert.*;

public class CompatibilityPlannerTest {
    private static GameDetector.Detection detect(List<GameDetector.Entry> e) {
        return GameDetector.analyze(e, false);
    }
    private static CompatibilityPlanner.Plan plan(List<GameDetector.Entry> e) {
        return CompatibilityPlanner.build(detect(e), GameManifestReader.analyze(Collections.emptyList()), e);
    }
    private static CompatibilityPlanner.Component component(CompatibilityPlanner.Plan p, String name) {
        for (CompatibilityPlanner.Component c : p.components) if (c.id.equals(name)) return c;
        throw new AssertionError("missing component: " + name);
    }
    @Test public void x86RequiresTranslationWithoutSpecificVersion() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Celestial Road.exe",false,5000000,"","","","x86-64",Collections.emptyList()));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"CPU_TRANSLATOR").decision.contains("مطلوبة"));
        assertTrue(p.launchReadiness.contains("غير جاهز"));
        assertFalse(component(p,"CPU_TRANSLATOR").reason.contains("FEX_20261012"));
    }
    @Test public void d3d11PointsToDxvkButNotAutoselectDriver() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Star Forge.exe",false,5000000,"","","","x86-64",Collections.singletonList("d3d11.dll")));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"DXVK").decision.contains("مرشح"));
        assertTrue(component(p,"VKD3D").decision.contains("غير محسوم"));
        assertTrue(component(p,"GPU_DRIVER").decision.contains("اختبار"));
    }
    @Test public void d3d12PointsToVkd3dButNotDxvk() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Star Forge.exe",false,5000000,"","","","x86-64",Collections.singletonList("d3d12.dll")));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"VKD3D").decision.contains("مرشح"));
        assertTrue(component(p,"DXVK").decision.contains("غير محسوم"));
    }
    @Test public void noImportsDoesNotMeanNoDirectX() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Game.exe",false,5000000));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"DXVK").decision.contains("غير محسوم"));
        assertTrue(component(p,"VKD3D").decision.contains("غير محسوم"));
        assertTrue(p.evidence.toString().contains("وقت التشغيل"));
    }
    @Test public void eacComponentDoesNotGetMistakenForGame() {
        List<GameDetector.Entry> e = Arrays.asList(new GameDetector.Entry("CarX Street/CarX Street.exe",false,5000000,"","","","x86-64",Collections.emptyList()),new GameDetector.Entry("CarX Street/EasyAntiCheat/EasyAntiCheat_EOS_Setup.exe",false,100000));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(p.protection.contains("Easy Anti-Cheat"));
        assertTrue(p.blockers.contains("الحماية"));
        assertFalse(p.launchReadiness.contains("جاهز للتشغيل الآن"));
    }
    @Test public void battleyeHintsAreNotSupportClaims() {
        List<GameDetector.Entry> e = Arrays.asList(new GameDetector.Entry("Skyfall.exe",false),new GameDetector.Entry("BattlEye/BEService.exe",false));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(p.protection.contains("BattlEye"));
        assertTrue(p.evidence.toString().contains("لا يثبت"));
    }
    @Test public void emptyDirectoryHasExplicitBlocker() {
        CompatibilityPlanner.Plan p = plan(Collections.emptyList());
        assertTrue(p.blockers.contains("لم يُحدد"));
    }
    @Test public void steamApiDllNeverMeansOwnership() {
        List<GameDetector.Entry> e = Arrays.asList(new GameDetector.Entry("SeaQuest.exe",false),new GameDetector.Entry("steam_api64.dll",false));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(p.store.contains("احتمال"));
        assertTrue(p.requirements.contains("غير متحققة"));
    }
    @Test public void bothApisRequireDisambiguation() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Apocalypse.exe",false,5000000,"","","","x86-64",Arrays.asList("d3d11.dll","d3d12.dll")));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"DXVK").decision.contains("مرشح"));
        assertTrue(component(p,"VKD3D").decision.contains("مرشح"));
        assertTrue(p.evidence.toString().contains("لا نختار المسار"));
    }
    @Test public void arm64ExecutablesShouldNotTriggerX86Translation() {
        List<GameDetector.Entry> e = Collections.singletonList(new GameDetector.Entry("Native.exe",false,5000000,"","","","arm64",Collections.emptyList()));
        CompatibilityPlanner.Plan p = plan(e);
        assertTrue(component(p,"CPU_TRANSLATOR").decision.contains("لا يتطلب"));
    }
}
