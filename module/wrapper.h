#if defined(__x86_64__)
#define PARAM1 di
#define PARAM2 si
#define PARAM3 dx
#define PARAM4 r10
#elif defined(__aarch64__)
#define PARAM1 regs[0]
#define PARAM2 regs[1]
#define PARAM3 regs[2]
#define PARAM4 regs[3]
#else
#error "Architecture not implemented"
#endif

#if ! defined(__aarch64__)
asmlinkage long x64_virt_open(struct pt_regs *regs) // (char *pathname, int flags, mode_t mode)
{
	return virt_open((char *)regs->PARAM1, (int)regs->PARAM2, (mode_t)regs->PARAM3);
}
#endif

asmlinkage long x64_virt_chdir(struct pt_regs *regs) // (char *path)
{
	return virt_chdir((char *)regs->PARAM1);
}

#if 0
asmlinkage long x64_virt_oldstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt_oldstat((char *)regs->PARAM1, (struct __old_kernel_stat *)regs->PARAM2);
}
#endif

#if ! defined(__aarch64__)
asmlinkage long x64_virt_access(struct pt_regs *regs) // (char *path, int amode)
{
	return virt_access((char *)regs->PARAM1, (int)regs->PARAM2);
}
#endif

#if 0
asmlinkage long x64_virt_oldlstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt_oldlstat((char *)regs->PARAM1, (struct __old_kernel_stat *)regs->PARAM2);
}
#endif

#if ! defined(__aarch64__)
asmlinkage long x64_virt_readlink(struct pt_regs *regs) // (char *path, char *buf, int bufsiz)
{
	return virt_readlink((char *)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3);
}

asmlinkage long x64_virt_stat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt_stat((char *)regs->PARAM1, (struct stat *)regs->PARAM2);
}

asmlinkage long x64_virt_lstat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt_lstat((char *)regs->PARAM1, (struct stat *)regs->PARAM2);
}
#endif

asmlinkage long x64_virt_getcwd(struct pt_regs *regs) // (char *buf, ulong size)
{
	return virt_getcwd((char *)regs->PARAM1, (ulong)regs->PARAM2);
}

#if 0
asmlinkage long x64_virt_stat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf)
{
	return virt_stat64((char *)regs->PARAM1, (struct stat64 *)regs->PARAM2);
}

asmlinkage long x64_virt_lstat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf, long flags)
{
	return virt_lstat64((char *)regs->PARAM1, (struct staty4 *)regs->PARAM2, (long)regs->PARAM3);
}
#endif

asmlinkage long x64_virt_getxattr(struct pt_regs *regs) // (char *path, char *name, void *value, ulong size)
{
	return virt_getxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (void *)regs->PARAM3, (ulong)regs->PARAM4);
}

asmlinkage long x64_virt_lgetxattr(struct pt_regs *regs) // (char *path, char *name, void *value, size_t size)
{
	return virt_lgetxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (void *)regs->PARAM3, (size_t)regs->PARAM4);
}

asmlinkage long x64_virt_listxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt_listxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (size_t)regs->PARAM3);
}

asmlinkage long x64_virt_llistxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt_llistxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (size_t)regs->PARAM3);
}

asmlinkage long x64_virt_openat(struct pt_regs *regs) // (int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt_openat((int)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3, (mode_t)regs->PARAM4);
}

#if 0
asmlinkage long x64_virt_fstatat64(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt_fstatat64((int)regs->PARAM1, (char *)regs->PARAM2, (struct stat *)regs->PARAM3, (int)regs->PARAM4);
}
#endif

#if defined(__x86_64__) || defined(__aarch64__)
asmlinkage long x64_virt_newfstatat(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt_newfstatat((int)regs->PARAM1, (char *)regs->PARAM2, (struct stat *)regs->PARAM3, (int)regs->PARAM4);
}
#endif

asmlinkage long x64_virt_readlinkat(struct pt_regs *regs) // (int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt_readlinkat((int)regs->PARAM1, (char *)regs->PARAM2, (char *)regs->PARAM3, (size_t)regs->PARAM4);
}

asmlinkage long x64_virt_faccessat(struct pt_regs *regs) // (int dirfd, char *pathname, int mode)
{
	return virt_faccessat((int)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3);
}

#define PACK_REGS1 \
	struct pt_regs regs; \
	regs.PARAM1 = (ulong)path;

#define PACK_REGS2 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	va_end(ap);

#define PACK_REGS3 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	regs.PARAM3 = va_arg(ap, ulong); \
	va_end(ap);

#define PACK_REGS4 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	regs.PARAM3 = va_arg(ap, ulong); \
	regs.PARAM4 = va_arg(ap, ulong); \
	va_end(ap);

#define PACK_REGSAT3 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)dirfd; \
	regs.PARAM2 = (ulong)path; \
	regs.PARAM3 = va_arg(ap, ulong); \
	va_end(ap);

#define PACK_REGSAT4 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)dirfd; \
	regs.PARAM2 = (ulong)path; \
	regs.PARAM3 = va_arg(ap, ulong); \
	regs.PARAM4 = va_arg(ap, ulong); \
	va_end(ap);

#if ! defined(__aarch64__)
asmlinkage long orig_open(char *path,...) // int flags, mode_t mode)
{
	PACK_REGS3
	return x64_orig_open(&regs);
}
#endif

asmlinkage long orig_chdir(char *path,...) // )
{
	PACK_REGS1
	return x64_orig_chdir(&regs);
}

#if 0
asmlinkage long orig_oldstat(char *path,...) //  struct __old_kernel_stat *statbuf)
{
	PACK_REGS2
	return x64_orig_oldstat(&regs);
}
#endif

#if ! defined(__aarch64__)
asmlinkage long orig_access(char *path,...) //  int amode)
{
	PACK_REGS2
	return x64_orig_access(&regs);
}
#endif

#if 0
asmlinkage long orig_oldlstat(char *path,...) //  struct __old_kernel_stat *statbuf)
{
	PACK_REGS2
	return x64_orig_oldlstat(&regs);
}
#endif

#if ! defined(__aarch64__)
asmlinkage long orig_readlink(char *path,...) //  char *buf, int bufsiz)
{
	PACK_REGS3
	return x64_orig_readlink(&regs);
}

asmlinkage long orig_stat(char *path,...) //  struct stat *statbuf)
{
	PACK_REGS2
	return x64_orig_stat(&regs);
}

asmlinkage long orig_lstat(char *path,...) //  struct stat *statbuf)
{
	PACK_REGS2
	return x64_orig_lstat(&regs);
}
#endif

asmlinkage long orig_getcwd(char *path,...) //  ulong size)
{
	PACK_REGS2
	return x64_orig_getcwd(&regs);
}

#if 0
asmlinkage long orig_stat64(char *path,...) //  struct stat64 *statbuf)
{
	PACK_REGS2
	return x64_orig_stat64(&regs);
}

asmlinkage long orig_lstat64(char *path,...) //  struct stat64 *statbuf, long flags)
{
	PACK_REGS3
	return x64_orig_lstat64(&regs);
}
#endif

asmlinkage long orig_getxattr(char *path,...) //  ulong name, void *value, ulong size)
{
	PACK_REGS4
	return x64_orig_getxattr(&regs);
}

asmlinkage long orig_lgetxattr(char *path,...) //  ulong name, void *value, size_t size)
{
	PACK_REGS4
	return x64_orig_lgetxattr(&regs);
}

asmlinkage long orig_listxattr(char *path,...) //  char *list, size_t size)
{
	PACK_REGS3
	return x64_orig_listxattr(&regs);
}

asmlinkage long orig_llistxattr(char *path,...) //  char *list, size_t size)
{
	PACK_REGS3
	return x64_orig_llistxattr(&regs);
}

asmlinkage long orig_openat(int dirfd, char *path,...) //  int flags, mode_t mode)
{
	PACK_REGSAT4
	return x64_orig_openat(&regs);
}

#if 0
asmlinkage long orig_fstatat64(int dirfd, char *path,...) //  struct stat *statbuf, int flag)
{
	PACK_REGSAT4
	return x64_orig_fstatat64(&regs);
}
#endif

#if defined(__x86_64__) || defined(__aarch64__)
asmlinkage long orig_newfstatat(int dirfd, char *path,...) //  struct stat *statbuf, int flag)
{
	PACK_REGSAT4
	return x64_orig_newfstatat(&regs);
}
#endif

asmlinkage long orig_readlinkat(int dirfd, char *path,...) //  char *buf, size_t bufsiz)
{
	PACK_REGSAT4
	return x64_orig_readlinkat(&regs);
}

asmlinkage long orig_faccessat(int dirfd, char *path,...) //  int mode)
{
	PACK_REGSAT3
	return x64_orig_faccessat(&regs);
}
