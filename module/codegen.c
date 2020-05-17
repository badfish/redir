#include <stdio.h>
#if defined(__x86_64__)
#define USE_32BIT_COMPAT 1
#include "arch/x86/include/generated/uapi/asm/unistd_32.h"
#elif defined(__aarch64__)
#define USE_32BIT_COMPAT 1
#include "arch/arm64/include/asm/unistd32.h"
#endif

int main(int argc, char **argv)
{
#if defined(USE_32BIT_COMPAT)
#define PROCESS(name, nargs) printf("#define __NR_32_"#name" %d\n", __NR_##name);
#define PROC_COMPAT_32
#include "list.h"
	printf("#define __NR_32_close %d\n", __NR_close);
#endif
	return 0;
}
