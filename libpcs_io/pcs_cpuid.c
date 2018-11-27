/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include "pcs_cpuid.h"
#include "pcs_config.h"
#include "bug.h"

/* not sure about exact gcc version, so put 4.4 from RHEL6 */
#if defined(__x86_64__) && (defined(__clang__) || GCC_VERSION >= 40400)

static inline void pcs_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	asm volatile("cpuid"
			: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
			: "0" (*eax), "2" (*ecx));
}

#elif defined(_WIN64)

#include <intrin.h>

static inline void pcs_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	int cpuid[4] = {0, 0, 0, 0};
	__cpuid(cpuid, *eax);

	(*eax) = cpuid[0];
	(*ebx) = cpuid[1];
	(*ecx) = cpuid[2];
	(*edx) = cpuid[3];
}

#else

static inline void pcs_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	(*eax) = 0;
	(*ebx) = 0;
	(*ecx) = 0;
	(*edx) = 0;
}

#endif

static int pcs_cpuid_max(void)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

	pcs_cpuid(&eax, &ebx, &ecx, &edx);
	return eax;
}

int pcs_is_crc32_sse_supported(void)
{
	if (pcs_cpuid_max() < 1)
		return 0;

	unsigned int eax = 1, ebx, ecx = 0, edx;

	pcs_cpuid(&eax, &ebx, &ecx, &edx);
	return !!(ecx & (1 << 20));	/* SSE4.2 support */
}

int pcs_is_avx2_supported(void)
{
	if (pcs_cpuid_max() < 7)
		return 0;

	unsigned int eax = 7, ebx = 0, ecx = 0, edx;

	pcs_cpuid(&eax, &ebx, &ecx, &edx);
	return !!(ebx & (1 << 5));	/* AVX2 support */
}

int pcs_is_aesni_supported(void)
{
	if (pcs_cpuid_max() < 1)
		return 0;

	unsigned int eax = 1, ebx, ecx = 0, edx;

	pcs_cpuid(&eax, &ebx, &ecx, &edx);
	return !!(ecx & (1 << 25));	/* AES-NI support */
}


#if defined(__aarch64__) || (__ARM_ARCH_7A__) || (__ARM_ARCH_8A__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

int pcs_cpu_is_neon_supported()
{
#ifdef __aarch64__
	unsigned int val = getauxval(AT_HWCAP);
	return val & HWCAP_ASIMD;
#elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_8A__)
	unsigned int val = getauxval(AT_HWCAP);
	return val & HWCAP_NEON;
#else
	BUG();
	return 0;
#endif
}

int pcs_cpu_is_arm_crc_supported()
{
#ifdef __aarch64__
	unsigned int val = getauxval(AT_HWCAP);
	return val & HWCAP_CRC32;
#elif defined(__ARM_ARCH_8A__)
	unsigned int val = getauxval(AT_HWCAP2);
	return val & HWCAP2_CRC32;
#else
	BUG();
	return 0;
#endif
}


int pcs_cpu_is_arm_pmull_supported()
{
#ifdef __aarch64__
	unsigned int val = getauxval(AT_HWCAP);
	return val & HWCAP_PMULL;
#elif defined(__ARM_ARCH_8A__)
	unsigned int val = getauxval(AT_HWCAP2);
	return val & HWCAP2_PMULL;
#else
	BUG();
	return 0;
#endif
}
