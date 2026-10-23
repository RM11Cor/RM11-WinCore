package com.rm11.autocore.runtime;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Uses the pinned FEX-2609 PE DLL symbol/RVA to identify deliberate FEX traps.
 * Does not modify Wine, FEX, game assets, memory, or crash-handling behaviour.
 */
public final class FexAssertionAnalyzer {
    // Checked against FEX-2609 PE binary SHA256 32c404fea3c5771408cb60d46f8d298717bb68eb721d32a86dcf1b3988bf42c8
    // llvm-objdump: 0x18017facc <FEXCore::Assert::ForcedAssert>: hlt #0x1
    public static final long PINNED_FORCED_ASSERT_RVA = 0x17faccl;
    private static final Pattern MAP = Pattern.compile(
            "mapping PE file [^\\r\\n]*?libarm64ecfex\\.dll[^\\r\\n]*? at 0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION = Pattern.compile(
            "Unhandled exception code\\s+c000001d[^\\r\\n]*?addr\\s+0x([0-9a-fA-F]+)",
            Pattern.CASE_INSENSITIVE);
    private FexAssertionAnalyzer() {}

    public static Finding inspect(String wineLog) {
        if (wineLog == null) return new Finding("NO_LOG", "", -1, -1, -1);
        Matcher crash = EXCEPTION.matcher(wineLog);
        if (!crash.find()) return new Finding("NO_C000001D_IN_CAPTURE", "", -1, -1, -1);
        long fault;
        try { fault = Long.parseUnsignedLong(crash.group(1), 16); }
        catch (NumberFormatException e) { return new Finding("MALFORMED_FAULT_ADDRESS", "", -1, -1, -1); }

        Matcher maps = MAP.matcher(wineLog);
        long base = -1, end = -1;
        while (maps.find()) {
            try {
                long candidateBase = Long.parseUnsignedLong(maps.group(1), 16);
                long candidateEnd = Long.parseUnsignedLong(maps.group(2), 16);
                if (candidateBase <= fault && fault < candidateEnd) {
                    base = candidateBase;
                    end = candidateEnd;
                    break;
                }
            } catch (NumberFormatException ignored) { }
        }
        if (base < 0) return new Finding("CRASH_IMAGE_MAPPING_NOT_CAPTURED", "", fault, -1, -1);
        long rva = fault - base;
        String status = rva == PINNED_FORCED_ASSERT_RVA
                ? "FEXCORE_FORCED_ASSERT_HLT1_CONFIRMED"
                : "ILLEGAL_INSTRUCTION_INSIDE_FEX_DLL_OTHER_OFFSET";
        return new Finding(status, "libarm64ecfex.dll", fault, base, rva);
    }

    public static final class Finding {
        public final String status;
        public final String image;
        public final long address;
        public final long base;
        public final long rva;

        private Finding(String status, String image, long address, long base, long rva) {
            this.status = status;
            this.image = image;
            this.address = address;
            this.base = base;
            this.rva = rva;
        }

        public String summary() {
            StringBuilder s = new StringBuilder("RM11_FEX_ASSERT_ANALYSIS_V264\n");
            s.append("status=").append(status).append('\n');
            if (!image.isEmpty()) s.append("image=").append(image).append('\n');
            if (address >= 0) s.append("crash_pc=").append(hex(address)).append('\n');
            if (base >= 0) s.append("image_base=").append(hex(base)).append('\n');
            if (rva >= 0) s.append("image_rva=").append(hex(rva)).append('\n');
            s.append("assertion_condition_identified=false\n");
            s.append("call_site_or_return_address_needed=true\n");
            s.append("Note: HLT #1 is a deliberate FEXCore assertion trap; do not patch it out.\n");
            return s.toString();
        }
    }

    private static String hex(long n) { return "0x" + Long.toHexString(n).toLowerCase(Locale.ROOT); }
}
