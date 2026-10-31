package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
public class R4WitcherDx12LayoutV49075Test {
    @Test public void maintainsRelativeContentAndDlcPathsWithoutModifyingGame()throws Exception{
        Path td=Files.createTempDirectory("r4-v49075");
        Path game=td.resolve("original");
        Path exe=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        Files.createDirectories(game.resolve("content"));
        Files.createDirectories(game.resolve("dlc"));
        Files.createDirectories(game.resolve("bin/config"));
        Files.write(exe,new byte[]{'M','Z',1,2});
        Path side=td.resolve("private/runtime-123");
        R4WitcherDx12LayoutV49075.Paths layout=
            R4WitcherDx12LayoutV49075.mirror(exe,side);
        assertEquals(side.resolve("bin/x64_dx12/witcher3.exe"),layout.localExe());
        assertEquals(side.resolve("content"),layout.localContent());
        assertTrue(Files.isDirectory(side.resolve("content")));
        assertFalse(Files.isSymbolicLink(side.resolve("content")));
        assertTrue(Files.isSymbolicLink(side.resolve("dlc")));
        assertTrue(Files.isSymbolicLink(side.resolve("bin/config")));
        assertEquals(side.resolve("content").toRealPath(),
            layout.localContent().toRealPath());
        assertEquals(game.resolve("bin/config").toRealPath(),
            side.resolve("bin/config").toRealPath());
        assertTrue(Files.isRegularFile(exe));
        assertFalse(Files.exists(layout.localExe()));
    }
    @Test public void shadowSkipsNestedEmptyLegacyFoldersAndPreservesAllFiles()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49112-empty-folders");
        Path game=td.resolve("game");
        Path source=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(source.getParent());
        Files.write(source,new byte[]{'M','Z',1});
        Path bundle=game.resolve("content/content0/bundles/pack.bundle");
        Files.createDirectories(bundle.getParent());
        byte[] originalBytes={1,2,3,4};
        Files.write(bundle,originalBytes);
        Path oldContent=game.resolve("content/content1/bundles");
        Path oldDlc=game.resolve("dlc/dlc1/bundles");
        Files.createDirectories(oldContent);
        Files.createDirectories(oldDlc);
        Path side=td.resolve("app-owned/wk3");
        R4WitcherDx12LayoutV49075.Paths r=
            R4WitcherDx12LayoutV49075.mirror(source,side);
        assertTrue(r.privateFolderShadowUsed);
        assertEquals(4,r.privateEmptyDirsPruned);
        assertFalse(Files.exists(side.resolve("content/content1")));
        assertFalse(Files.exists(side.resolve("dlc/dlc1")));
        assertTrue(Files.exists(game.resolve("content/content1")));
        assertTrue(Files.isDirectory(oldContent));
        assertTrue(Files.isDirectory(oldDlc));
        assertArrayEquals(originalBytes,
            Files.readAllBytes(side.resolve("content/content0/bundles/pack.bundle")));
        assertTrue(Files.isSymbolicLink(side.resolve(
            "content/content0/bundles/pack.bundle")));
        assertArrayEquals(originalBytes,Files.readAllBytes(bundle));
    }
    @Test public void upgradesExistingPrivateLinkWithoutTouchingOriginalAndIsIdempotent()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49112-link-upgrade");
        Path game=td.resolve("game");
        Path exe=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        Files.write(exe,new byte[]{'M','Z',1});
        Path bundle=game.resolve("content/content0/pack.bundle");
        Files.createDirectories(bundle.getParent());
        byte[] sourceBytes={7,8,9};
        Files.write(bundle,sourceBytes);
        Files.createDirectories(game.resolve("dlc"));
        Path stage=td.resolve("app-private/stage");
        Files.createDirectories(stage);
        // Simulate a real RC181/RC182 install that still has the older
        // app-private content-root symlink. Upgrade it without touching source.
        Files.createSymbolicLink(stage.resolve("content"),
            game.resolve("content").toRealPath());
        assertTrue(Files.isSymbolicLink(stage.resolve("content")));
        Path obsolete=game.resolve("content/legacy/old-empty-folder");
        Files.createDirectories(obsolete);
        R4WitcherDx12LayoutV49075.Paths migrated=
            R4WitcherDx12LayoutV49075.mirror(exe,stage);
        assertTrue(migrated.privateFolderShadowUsed);
        assertFalse(Files.isSymbolicLink(stage.resolve("content")));
        assertFalse(Files.exists(stage.resolve("content/legacy")));
        assertTrue(Files.isDirectory(obsolete));
        assertArrayEquals(sourceBytes,Files.readAllBytes(bundle));
        assertArrayEquals(sourceBytes,
            Files.readAllBytes(stage.resolve("content/content0/pack.bundle")));
        R4WitcherDx12LayoutV49075.mirror(exe,stage);
        assertTrue(Files.isRegularFile(bundle));
        assertTrue(Files.isDirectory(obsolete));
    }
    @Test public void mutableContentMetadataIsPrivateAndCannotWriteThroughToGame()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49114-private-metadata");
        Path game=td.resolve("game");
        Path exe=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        Files.write(exe,new byte[]{'M','Z',1});
        Path metadata=game.resolve("content/metadata.store");
        Files.createDirectories(metadata.getParent());
        byte[] original={2,4,6,8};
        Files.write(metadata,original);
        Path stage=td.resolve("app-private/witcher");
        R4WitcherDx12LayoutV49075.mirror(exe,stage);
        Path privateMeta=stage.resolve("content/metadata.store");
        assertTrue(Files.isRegularFile(privateMeta));
        assertFalse(Files.isSymbolicLink(privateMeta));
        Files.write(privateMeta,new byte[]{7,7,7});
        assertArrayEquals(original,Files.readAllBytes(metadata));
        R4WitcherDx12LayoutV49075.mirror(exe,stage);
        assertArrayEquals(new byte[]{7,7,7},Files.readAllBytes(privateMeta));
        assertArrayEquals(original,Files.readAllBytes(metadata));
    }
    @Test public void remastered50HidesNonEmptyOldDataAndDlcWithoutDeletingGame()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49116-remastered");
        Path game=td.resolve("game");
        Path exe=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        // Sparse EXE of the known 5.0 length; no copyrighted game bytes.
        try(java.io.RandomAccessFile out=new java.io.RandomAccessFile(
                exe.toFile(),"rw")){
            out.write(new byte[]{'M','Z'});
            out.setLength(90832336L);
        }
        Path current=game.resolve("content/content0/bundles/new.bundle");
        Path obsolete=game.resolve("content/content7/bundles/old.bundle");
        Path oldDlc=game.resolve("dlc/old-dlc/content/bundles/old.bundle");
        Path metadata=game.resolve("content/metadata.store");
        for(Path item:new Path[]{current,obsolete,oldDlc,metadata})
            Files.createDirectories(item.getParent());
        Files.write(current,new byte[]{1,2,3});
        Files.write(obsolete,new byte[]{4,5});
        Files.write(oldDlc,new byte[]{6,7});
        byte[] originalMeta=new byte[5000];
        originalMeta[0]=53;
        Files.write(metadata,originalMeta);
        Path stage=td.resolve("private/remaster");
        R4WitcherDx12LayoutV49075.Paths layout=R4WitcherDx12LayoutV49075.mirror(exe,stage);
        assertTrue(layout.remastered50Detected);
        assertTrue(layout.remasteredLegacyDirsExcluded>=2);
        assertFalse(Files.exists(stage.resolve("content/content7")));
        assertFalse(Files.exists(stage.resolve("dlc")));
        assertArrayEquals(new byte[]{1,2,3},Files.readAllBytes(
            stage.resolve("content/content0/bundles/new.bundle")));
        assertArrayEquals(new byte[]{4,5},Files.readAllBytes(obsolete));
        assertArrayEquals(new byte[]{6,7},Files.readAllBytes(oldDlc));
        Path privateMeta=stage.resolve("content/metadata.store");
        assertFalse(Files.isSymbolicLink(privateMeta));
        Files.write(privateMeta,new byte[24]); // simulate failed index rebuild
        layout=R4WitcherDx12LayoutV49075.mirror(exe,stage);
        assertEquals(5000L,layout.metadataPrivateBytes);
        assertArrayEquals(originalMeta,Files.readAllBytes(metadata));
    }
    @Test public void recognizesNewDx12OnlyHotfixButNeverMislabelsOldDualApi()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49116-recent-hotfix");
        Path exe=td.resolve("game/bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        try(java.io.RandomAccessFile out=new java.io.RandomAccessFile(
                exe.toFile(),"rw")){out.setLength(90701824L);}
        Path game=td.resolve("game");
        Path meta=game.resolve("content/metadata.store");
        Files.createDirectories(game.resolve("content/content0"));
        Files.write(meta,new byte[6000]);
        assertTrue(R4WitcherDx12LayoutV49075.isRemastered50Layout(exe,game));
        Path classic=game.resolve("bin/x64/witcher3.exe");
        Files.createDirectories(classic.getParent());
        Files.write(classic,new byte[]{'M','Z',1});
        assertFalse(R4WitcherDx12LayoutV49075.isRemastered50Layout(exe,game));
    }
    @Test public void failsClosedOnCorruptedOriginalRemasteredMetadata()
            throws Exception{
        Path td=Files.createTempDirectory("r4-v49116-corrupt-meta");
        Path exe=td.resolve("game/bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        try(java.io.RandomAccessFile out=new java.io.RandomAccessFile(
                exe.toFile(),"rw")){out.setLength(90674640L);}
        Path meta=td.resolve("game/content/metadata.store");
        Files.createDirectories(meta.getParent());
        Files.write(meta,new byte[24]);
        try{
            R4WitcherDx12LayoutV49075.mirror(exe,td.resolve("private"));
            fail("must not silently run against a 24-byte broken index");
        }catch(java.io.IOException expected){
            assertEquals("WITCHER_REMASTERED_SOURCE_METADATA_CORRUPTED_REPAIR_REQUIRED",
                expected.getMessage());
        }
        assertEquals(24L,Files.size(meta));
    }
    @Test public void preservesExistingClassicDx11RelativeAssets()throws Exception{
        Path td=Files.createTempDirectory("r4-v49089-classic");
        Path game=td.resolve("original");
        Path dx11=game.resolve("bin/x64/witcher3.exe");
        Files.createDirectories(dx11.getParent());
        Files.createDirectories(game.resolve("content"));
        Files.createDirectories(game.resolve("dlc"));
        Files.createDirectories(game.resolve("bin/config"));
        byte[] pe=new byte[1024];pe[0]='M';pe[1]='Z';
        Files.write(dx11,pe);
        Path stage=td.resolve("private/dx11-stage");
        R4WitcherDx12LayoutV49075.Paths mirror=
            R4WitcherDx12LayoutV49075.mirrorClassicDx11(dx11,stage);
        assertEquals(stage.resolve("bin/x64/witcher3.exe"),mirror.localExe());
        assertEquals(game.resolve("content").toRealPath(),
            mirror.localContent().toRealPath());
        assertTrue(Files.isSymbolicLink(stage.resolve("dlc")));
        assertTrue(Files.isSymbolicLink(stage.resolve("bin/config")));
        assertFalse(Files.exists(mirror.localExe()));
        assertTrue(Files.isRegularFile(dx11));
    }
    @Test public void refusesNonWitcherGameLayouts()throws Exception{
        Path td=Files.createTempDirectory("r4-v49075-other");
        try{
            R4WitcherDx12LayoutV49075.plan(
                td.resolve("Silksong.exe"),td.resolve("stage"));
            fail("Must reject non-Witcher games");
        }catch(java.io.IOException good){
            assertEquals("NOT_A_WITCHER3_DX12_EXE",good.getMessage());
        }
    }
}
