#include "config.h"
#include "cpusupport.h"

#ifdef CPUSUPPORT_X86_CPUID
#ifdef WIN_CPUID
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#define CPUID_AESNI_BIT (1 << 25)
#endif

CPUSUPPORT_FEATURE_DECL(x86, aesni)
{
#ifdef CPUSUPPORT_X86_CPUID
#ifdef WIN_CPUID
	int registers[4];
	__cpuid(registers, 0);
	if (registers[0] < 1)
		goto unsupported;
	__cpuid(registers, 1);
	return ((registers[2] & CPUID_AESNI_BIT) ? 1 : 0);
#else
	unsigned int eax, ebx, ecx, edx;

	/* Check if CPUID supports the level we need. */
	if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx))
		goto unsupported;
	if (eax < 1)
		goto unsupported;

	/* Ask about CPU features. */
	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		goto unsupported;

	/* Return the relevant feature bit. */
	return ((ecx & CPUID_AESNI_BIT) ? 1 : 0);
#endif

unsupported:
#endif
	return (0);
}
