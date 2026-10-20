package com.rm11.autocore;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

/** No game-title registry: all examples are unknown to the implementation. */
public class GameDetectorTest {
    @Test public void identifiesAnyNewGameByExecutableFileName() {
        GameDetector.Detection r = GameDetector.analyze(Arrays.asList(
                new GameDetector.Entry("Neon Odyssey 2049/NeonOdyssey2049.exe", false, 9000000),
                new GameDetector.Entry("Neon Odyssey 2049/NeonOdyssey2049_Data", true)), false);
        assertEquals("Neon Odyssey 2049", r.title);
        assertEquals("neon-odyssey-2049", r.gameId);
        assertEquals("Neon Odyssey 2049/NeonOdyssey2049.exe", r.exe);
        assertTrue(r.certainty.contains("استنتاج"));
    }
    @Test public void prefersInternalProductMetadataOverExeName() {
        GameDetector.Detection r = GameDetector.analyze(Collections.singletonList(
                new GameDetector.Entry("bin/Game.exe", false, 20000000,
                        "Sunset Ruins: Chapter Two", "", "1.2.3.4")), false);
        assertEquals("Sunset Ruins: Chapter Two", r.title);
        assertEquals("1.2.3.4", r.version);
        assertTrue(r.certainty.contains("ProductName"));
    }
    @Test public void genericExeCanUseParentDirectoryWithLowConfidence() {
        GameDetector.Detection r = GameDetector.analyze(Collections.singletonList(
                new GameDetector.Entry("Starlight Adventures/Game.exe", false, 25000000)), false);
        assertEquals("Starlight Adventures", r.title);
        assertTrue(r.certainty.contains("منخفض"));
    }
    @Test public void ignoresCrashesAndInstallers() {
        GameDetector.Detection r = GameDetector.analyze(Arrays.asList(
                new GameDetector.Entry("Installer/setup.exe", false, 70000),
                new GameDetector.Entry("NovaRealm/NovaRealm.exe", false, 30000000),
                new GameDetector.Entry("NovaRealm/UnityCrashHandler64.exe", false, 100000)), false);
        assertEquals("Nova Realm", r.title);
        assertEquals("NovaRealm/NovaRealm.exe", r.exe);
    }
    @Test public void steamDllNotLicenseEvidence() {
        GameDetector.Detection r = GameDetector.analyze(Arrays.asList(
                new GameDetector.Entry("Silent Star.exe", false),
                new GameDetector.Entry("steam_api64.dll", false)), false);
        assertTrue(r.platform.contains("احتمال"));
        assertFalse(r.platform.contains("مرخّصة"));
    }
    @Test public void incompleteScanStaysQualified() {
        GameDetector.Detection r = GameDetector.analyze(Collections.singletonList(
                new GameDetector.Entry("BrandNewTitle.exe", false)), true);
        assertTrue(r.truncated);
        assertFalse(r.evidence.isEmpty());
    }
    @Test public void emptyFolderHasNoExecutable() {
        GameDetector.Detection r = GameDetector.analyze(Collections.emptyList(), false);
        assertEquals("unresolved", r.gameId);
        assertEquals("", r.exe);
    }
    @Test public void recognizesUnityFromStructureWithoutGameList() {
        GameDetector.Detection r = GameDetector.analyze(Arrays.asList(
                new GameDetector.Entry("Silver Isles/SilverIsles.exe", false),
                new GameDetector.Entry("Silver Isles/SilverIsles_Data/globalgamemanagers", false),
                new GameDetector.Entry("Silver Isles/UnityPlayer.dll", false)), false);
        assertTrue(r.engine.contains("Unity"));
        assertEquals("Silver Isles", r.title);
    }
    @Test public void recognizesUnrealFromStructureWithoutGameList() {
        GameDetector.Detection r = GameDetector.analyze(Arrays.asList(
                new GameDetector.Entry("Mystery/Rift-Win64-Shipping.exe", false),
                new GameDetector.Entry("Mystery/Engine/Binaries/Win64/Engine.dll", false)), false);
        assertTrue(r.engine.contains("Unreal"));
    }
    @Test public void directXImportedDllIsHintNotValidatedConfiguration() {
        GameDetector.Detection r = GameDetector.analyze(Collections.singletonList(
                new GameDetector.Entry("Arctic Voyage.exe", false, 3300000, "", "", "",
                        "x86-64", Collections.singletonList("d3d12.dll"))), false);
        assertTrue(r.graphics.contains("DirectX 12"));
        assertTrue(r.graphics.contains("قرينة"));
        assertEquals("x86-64", r.architecture);
    }
    @Test public void unidentifiedGraphicsRemainUnknown() {
        GameDetector.Detection r = GameDetector.analyze(Collections.singletonList(
                new GameDetector.Entry("Arctic Voyage.exe", false, 3300000)), false);
        assertTrue(r.graphics.contains("غير محدد"));
    }
}
