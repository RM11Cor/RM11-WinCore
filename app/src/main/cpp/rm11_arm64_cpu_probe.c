/*
 * RM11 v2.6.5 - read-only device CPU ID register probe.
 * This PIE is executed from Android's signed APK native library directory.
 * It never writes system files or touches Wine registry itself.
 *
 * Linux arm64 HWCAP_CPUID advertises EL0 access to sanitized ID registers.
 * If the kernel denies an MRS instruction, the isolated child terminates and
 * Java MUST NOT modify the Wine registry. No artificial CPU feature values.
 */
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/auxv.h>
#include <asm/hwcap.h>

#ifndef HWCAP_CPUID
#define HWCAP_CPUID (1UL << 11)
#endif

#ifndef HWCAP_SVE
#define HWCAP_SVE (1UL << 22)
#endif

#define SYSREG(NAME, REG) static inline uint64_t read_##NAME(void) { \
    uint64_t n; __asm__ volatile("mrs %0, " #REG : "=r"(n)); return n; \
}

SYSREG(isar0, ID_AA64ISAR0_EL1)
SYSREG(isar1, ID_AA64ISAR1_EL1)
SYSREG(isar2, ID_AA64ISAR2_EL1)
SYSREG(pfr0, ID_AA64PFR0_EL1)
SYSREG(pfr1, ID_AA64PFR1_EL1)
SYSREG(mmfr0, ID_AA64MMFR0_EL1)
SYSREG(mmfr1, ID_AA64MMFR1_EL1)
SYSREG(mmfr2, ID_AA64MMFR2_EL1)
SYSREG(zfr0, S3_0_C0_C4_4)
SYSREG(midr, MIDR_EL1)
SYSREG(ctr, CTR_EL0)

static void output(const char *name, uint64_t value) {
    printf("%s=%016" PRIx64 "\n", name, value);
}

int main(void) {
    const unsigned long hwcap = getauxval(AT_HWCAP);
    if (!(hwcap & HWCAP_CPUID)) {
        fputs("RM11_CPU_ID_STATUS=KERNEL_CPUID_NOT_EXPOSED\n", stdout);
        return 21;
    }
    /* A successful exit only occurs if EVERY required register could be read.
     * All reads are sanitized by Linux kernel EL0 ID-register emulation.
     */
    const uint64_t isar0=read_isar0();
    const uint64_t isar1=read_isar1();
    const uint64_t isar2=read_isar2();
    const uint64_t pfr0=read_pfr0();
    const uint64_t pfr1=read_pfr1();
    const uint64_t mmfr0=read_mmfr0();
    const uint64_t mmfr1=read_mmfr1();
    const uint64_t mmfr2=read_mmfr2();
    const uint64_t zfr0=(hwcap & HWCAP_SVE) ? read_zfr0() : 0;
    const uint64_t midr=read_midr();
    const uint64_t ctr=read_ctr();

    if (midr == 0 || ctr == 0) {
        fputs("RM11_CPU_ID_STATUS=INVALID_CORE_ID_OR_CACHE_TYPE\n", stdout);
        return 22;
    }

    puts("RM11_CPU_ID_STATUS=MEASURED_EL0_HWCAP_CPUID");
    output("CP 4030", isar0);
    output("CP 4020", pfr0);
    output("CP 4021", pfr1);
    output("CP 4031", isar1);
    output("CP 4038", mmfr0);
    output("CP 403A", mmfr2);
    output("CP 4024", zfr0);
    output("CP 4039", mmfr1);
    output("CP 4032", isar2);
    output("CP 5801", ctr);
    output("CP 4000", midr);
    return 0;
}
