package com.rm11.autocore;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

/** Generic metadata extraction tests. All titles are arbitrary synthetic examples. */
public class GameManifestReaderTest {
    private GameManifestReader.Result parsed(String path, String text) {
        return GameManifestReader.analyze(Collections.singletonList(new GameManifestReader.Document(path, text)));
    }
    @Test public void steamManifestContainsNameAndAppIdWithoutLicenseAssumption() {
        GameManifestReader.Result r = parsed("steamapps/appmanifest_95123.acf",
                "\"AppState\"\n{\"appid\" \"95123\"\n\"name\" \"Moonlight City\"\n\"buildid\" \"555\"}");
        assertEquals("Moonlight City",r.title);
        assertEquals("95123",r.steamAppId);
        assertTrue(r.platform.contains("لا يثبت الترخيص"));
    }
    @Test public void arbitraryUnityGameInfoCanProvideTitle() {
        assertEquals("Amber Canyons",parsed("Amber_Data/app.info","Studio\nAmber Canyons\n").title);
    }
    @Test public void epicAndGogMetadataAreRecognized() {
        assertEquals("Ocean Velocity",parsed(".egstore/12.item","{\"DisplayName\":\"Ocean Velocity\"}").title);
        assertEquals("Desert Echo",parsed("goggame-123456.info","{\"name\":\"Desert Echo\"}").title);
    }
    @Test public void unrealProjectDisplayTitleIsRead() {
        assertEquals("Northern Sky",parsed("Config/DefaultGame.ini",
                "ProjectDisplayedTitle=NSLOCTEXT(\"X\",\"Y\",\"Northern Sky\")").title);
    }
    @Test public void rejectLargeOrUnrelatedFiles() {
        assertFalse(GameManifestReader.accepts("Game/World.pak",999999));
        assertFalse(GameManifestReader.accepts("Game/random.ini",120));
        assertTrue(GameManifestReader.accepts("Game_Data/app.info",250));
    }
    @Test public void metadataTakesPriorityOverGenericExe() {
        GameDetector.Detection d=GameDetector.analyze(
                Collections.singletonList(new GameDetector.Entry("Game/Game.exe",false,9000000)),false,
                parsed("Game_Data/app.info","Studio\nReal Unknown Game Title\n"));
        assertEquals("Real Unknown Game Title",d.title);
    }
    @Test public void launchedExeSuffixDoesNotPolluteTitle() {
        GameDetector.Detection d=GameDetector.analyze(
                Collections.singletonList(new GameDetector.Entry("CarX Street Launcher.exe",false,9000000)),false);
        assertEquals("CarX Street",d.title);
    }
    @Test public void antiCheatBootstrapperCannotOverrideUnityGameTitle() {
        GameDetector.Detection d = GameDetector.analyze(Arrays.asList(
            new GameDetector.Entry("CarX Street Launcher.exe", false, 180000,
                "Easy Anti-Cheat Bootstrapper (EOS)", "Easy Anti-Cheat Bootstrapper", "1.9.4",
                "x86-64", Arrays.asList("kernel32.dll", "user32.dll")),
            new GameDetector.Entry("CarX Street Launcher_Data/app.info", false, 32),
            new GameDetector.Entry("CarX Street Launcher_Data/globalgamemanagers", false, 3200000),
            new GameDetector.Entry("EasyAntiCheat_EOS/EasyAntiCheat_EOS.exe", false, 980000)),false,
            parsed("CarX Street Launcher_Data/app.info", "CarX Studio\nCarX Street\n"));
        assertEquals("CarX Street", d.title);
        assertEquals("carx-street", d.gameId);
        assertEquals("CarX Street Launcher.exe", d.exe);
        assertEquals("غير محدد", d.version);
        assertTrue(String.join(" ", d.evidence).contains("Easy Anti-Cheat"));
        assertTrue(String.join(" ", d.evidence).contains("ليس إصدار اللعبة"));
    }
    @Test public void genericLauncherMetadataWinsOverAntiCheatPeTitle() {
        GameDetector.Detection d= GameDetector.analyze(Collections.singletonList(
            new GameDetector.Entry("Games/Launcher.exe",false,110000,
                "Easy Anti-Cheat Bootstrapper (EOS)", "EAC Client", "1.9.4")), false,
            parsed("Games/Launcher_Data/app.info","Developer\nUntitled Horizon\n"));
        assertEquals("Untitled Horizon", d.title);
        assertEquals("غير محدد", d.version);
    }
    @Test public void noManifestDoesNotTreatAntiCheatAsGameName() {
        GameDetector.Detection d=GameDetector.analyze(Collections.singletonList(
            new GameDetector.Entry("New Trails/NewTrails Launcher.exe",false,100000,
            "Easy Anti-Cheat Bootstrapper (EOS)", "EAC", "1.9.4")),false);
        assertEquals("New Trails", d.title);
        assertFalse(d.title.toLowerCase().contains("anti-cheat"));
        assertEquals("غير محدد",d.version);
    }
    @Test public void metadataHintChoosesMatchingExeOverOtherCandidate() {
        GameDetector.Detection d=GameDetector.analyze(Arrays.asList(
            new GameDetector.Entry("bin/Other Game.exe",false,25000000,"Other Product","",""),
            new GameDetector.Entry("New World 4 Launcher.exe",false,11000000,"","", "")),false,
            parsed("New World 4 Launcher_Data/app.info","Publisher\nNew World 4\n"));
        assertEquals("New World 4",d.title);
        assertEquals("New World 4 Launcher.exe",d.exe);
    }
    @Test public void exeProductNameWithManifestConflictIsReported() {
        GameDetector.Detection d=GameDetector.analyze(
                Collections.singletonList(new GameDetector.Entry("Game.exe",false,9000000,
                        "True Product Name", "", "1.0")),false,
                parsed("steamapps/appmanifest_12345.acf","\"name\" \"Conflicting Title\""));
        assertEquals("Conflicting Title",d.title);
        assertTrue(String.join(" ",d.evidence).contains("تعارض"));
    }
}
