/*
 This is a list of the system calls that the strace() program has
 marked in its source code as taking a file name as an argument.
 System calls that we don't support (mostly because they modify
 the named file) are wrapped with the IGNORE() macro; the calls
 that we support are wrapped with the PROCESS() macro.

 The only purpose of the IGNORE macro is to remind us that we have 
 not forgotten the system call, but have deliberately excluded it.

 If PROC_COMPAT_32 is defined, the system calls
 for 32-bit compatibility mode are used.
*/

/* define the IGNORE macro to do nothing */
#define IGNORE(name)

/* for convenience the xxxat() functions have their own variant macro */
#if ! defined(PROCESSAT)
#define PROCESSAT(name, nargs) PROCESS(name, nargs)
#endif

/* flags for processor dependence */
#if defined(PROC_COMPAT_32)

#if defined(__x86_64__)
#define PROC_I386
#elif defined(__aarch64__)
#define PROC_ARM
#else
#error "Architecture not implemented"
#endif

#else

#if defined(__i386__)
#define PROC_I386
#elif defined(__x86_64__)
#define PROC_X86_64
#elif defined(__arm__)
#define PROC_ARM
#elif defined(__aarch64__)
#define PROC_AARCH64
#else
#error "Architecture not implemented"
#endif

#endif

#if ! defined(PROC_AARCH64)
PROCESS(open, 3)
#endif
IGNORE(creat)
IGNORE(link)
IGNORE(unlink)
IGNORE(execve)
PROCESS(chdir, 1)
IGNORE(mknod)
IGNORE(chmod)
IGNORE(lchown)
#if defined(PROC_I386)
PROCESS(oldstat, 2)
#endif
IGNORE(mount)
IGNORE(oldumount)
IGNORE(utime)
#if ! defined(PROC_AARCH64)
PROCESS(access, 2)
#endif
IGNORE(rename)
IGNORE(mkdir)
IGNORE(rmdir)
IGNORE(acct)
IGNORE(umount)
IGNORE(chroot)
IGNORE(symlink)
#if defined(PROC_I386)
PROCESS(oldlstat, 2)
#endif
#if ! defined(PROC_AARCH64)
PROCESS(readlink, 3)
#endif
IGNORE(uselib)
IGNORE(swapon)
IGNORE(truncate)
IGNORE(statfs)
#if ! defined(PROC_AARCH64)
PROCESS(stat, 2)
PROCESS(lstat, 2)
#endif
IGNORE(chown)
PROCESS(getcwd, 2)
IGNORE(truncate64)
#if defined(PROC_I386) || defined(PROC_ARM)
PROCESS(stat64, 2)
PROCESS(lstat64, 3)
#endif
IGNORE(lchown32)
IGNORE(chown32)
IGNORE(pivot_root)
IGNORE(setxattr)
IGNORE(lsetxattr)
PROCESS(getxattr, 4)
PROCESS(lgetxattr, 4)
PROCESS(listxattr, 3)
PROCESS(llistxattr, 3)
IGNORE(removexattr)
IGNORE(lremovexattr)
IGNORE(statfs64)
IGNORE(utimes)
PROCESSAT(openat, 4)
IGNORE(mkdirat)
IGNORE(mknodat)
IGNORE(fchownat)
IGNORE(futimesat)
#if defined(PROC_I386) || defined(PROC_ARM)
PROCESSAT(fstatat64, 4)
#endif
#if defined(PROC_X86_64) || defined(PROC_AARCH64)
PROCESSAT(newfstatat, 4)
#endif
IGNORE(unlinkat)
IGNORE(renameat)
IGNORE(linkat)
IGNORE(symlinkat)
PROCESSAT(readlinkat, 4)
IGNORE(fchmodat)
PROCESSAT(faccessat, 3)
IGNORE(utimensat)
IGNORE(fallocate)

/* undefine PROCESS so we can use it again to do something different */
#undef PROCESS
#undef PROCESSAT

/* undefine the processor flags */
#undef PROC_COMPAT_32
#undef PROC_I386
#undef PROC_X86_64
#undef PROC_ARM
#undef PROC_AARCH64
