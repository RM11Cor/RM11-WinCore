package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.file.Paths;

public final class GameDocumentPathPolicyTest {
    private static final java.nio.file.Path ROOT=Paths.get("/storage/emulated/0");
    @Test public void primaryGameFolderCanBeResolvedWithoutCopying() throws Exception {
        assertEquals(ROOT.resolve("Games/My Game/Game.exe"),
            GameDocumentPathPolicy.resolvePrimary("com.android.externalstorage.documents",
                    "primary:Games/My Game/Game.exe","Game.exe",ROOT));
    }
    @Test public void rejectsTraversalAndUntrustedProvider() throws Exception {
        for(String doc:new String[]{"primary:../../outside.exe","primary:/root.exe",
                "primary:Games/../outside.exe","primary:Games\\escape.exe"}) {
            try {
                GameDocumentPathPolicy.resolvePrimary("com.android.externalstorage.documents",
                        doc, "outside.exe",ROOT);
                if (!doc.equals("primary:Games/../outside.exe"))
                    fail("accepted unsafe "+doc);
            }catch(IOException expected){}
        }
        try {
            GameDocumentPathPolicy.resolvePrimary("com.android.providers.downloads.documents",
                    "raw:/sdcard/Game.exe","Game.exe",ROOT);
            fail("accepted outside SAF provider");
        }catch(IOException expected){}
    }
    @Test public void rejectsMismatchedNames() {
        try {
            GameDocumentPathPolicy.resolvePrimary("com.android.externalstorage.documents",
                    "primary:Games/Actual.exe","Fake.exe",ROOT);
            fail("accepted renamed URI");
        }catch(IOException expected){}
    }
}
