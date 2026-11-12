package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class PeForwarderTargetCheckTest {
    private static PeExportIndex.Result fixture(boolean forwarded) throws Exception {
        byte[] b=PeExportLinkTest.dll();
        if(forwarded) ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(4096+0x204,0x1190);
        Path f=Files.createTempFile("fh5-forward-target", ".dll");
        try {
            Files.write(f,b);
            try(SeekableByteChannel ch=Files.newByteChannel(f,StandardOpenOption.READ)) {
                return PeExportIndex.inspect(ch);
            }
        } finally {Files.deleteIfExists(f);}
    }
    private static PeForwarderProbe.Target target(String symbol,boolean ordinal) {
        return new PeForwarderProbe.Target("agsInitialize",
             "FORWARDER_TARGET_DECODED","amd_ags_x64_cdx."+symbol,
             "amd_ags_x64_cdx",symbol,ordinal);
    }
    private static PeForwarderTargetCheck.Result checked(
             String symbol,boolean ordinal,boolean forwarded) throws Exception {
        Map<String,PeExportIndex.Result> indices=new HashMap<>();
        indices.put("amd_ags_x64_cdx.dll",fixture(forwarded));
        return PeForwarderTargetCheck.assess(target(symbol,ordinal),indices,
            Collections.singleton("amd_ags_x64_cdx.dll"));
    }
    @Test public void targetNamedExportConfirmedInRealSyntheticPeTable() throws Exception {
        PeForwarderTargetCheck.Result r=checked("CreateFileW",false,false);
        assertEquals(PeForwarderTargetCheck.DIRECT,r.status);
        assertTrue(r.targetFileVisible);
        assertFalse(r.actualGameExecuted);
        assertFalse(r.abiVerified);
        assertFalse(r.iatWritten);
    }
    @Test public void targetOrdinalConfirmedWithDllBase() throws Exception {
        assertEquals(PeForwarderTargetCheck.DIRECT,checked("#38",true,false).status);
        assertEquals(PeForwarderTargetCheck.MISSING,checked("#1",true,false).status);
    }
    @Test public void anotherForwardedTargetMustNotClaimExecutable() throws Exception {
        assertEquals(PeForwarderTargetCheck.CHAIN,checked("CreateFileW",false,true).status);
    }
    @Test public void targetExportAbsenceIsNotHidden() throws Exception {
        assertEquals(PeForwarderTargetCheck.MISSING,checked("agsNonexistent",false,false).status);
    }
    @Test public void absentTargetDllIsDistinctFromAbsentExport() throws Exception {
        PeForwarderTargetCheck.Result r=PeForwarderTargetCheck.assess(
            target("CreateFileW",false),Collections.emptyMap(),Collections.emptySet());
        assertEquals(PeForwarderTargetCheck.NO_FILE,r.status);
    }
    @Test public void targetHasMissingOrIncompleteIndex() throws Exception {
        PeForwarderTargetCheck.Result r=PeForwarderTargetCheck.assess(
            target("CreateFileW",false),Collections.emptyMap(),
            Collections.singleton("amd_ags_x64_cdx.dll"));
        assertEquals(PeForwarderTargetCheck.INCOMPLETE,r.status);
    }
    @Test public void maliciousModuleNameIsRejected() {
        PeForwarderProbe.Target t=new PeForwarderProbe.Target("foo",
            "FORWARDER_TARGET_DECODED","../private.dll.Func",
            "../private","Func",false);
        PeForwarderTargetCheck.Result r=PeForwarderTargetCheck.assess(
            t,Collections.emptyMap(),Collections.emptySet());
        assertEquals(PeForwarderTargetCheck.BAD_TARGET,r.status);
    }
}
