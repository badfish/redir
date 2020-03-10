/*
 This is a list of the system calls that the strace() program has
 marked in its source code as taking a file name as an argument.
 System calls that we don't support (mostly because they modify
 the named file) are wrapped with the IGNORE() macro; the calls
 that we support are wrapped with the PROCESS() macro.

 The only purpose of the IGNORE macro is to remind us that we have 
 not forgotten the system call, but have deliberately excluded it.
*/

/* define the IGNORE macro to do nothing */
#define IGNORE(name)

/* for convenience the xxxat() functions have their own variant macro */
#if ! defined(PROCESSAT)
#define PROCESSAT(name) PROCESS(name)
#endif

#if ! defined(__aarch64__)
PROCESS(open)
#endif
IGNORE(creat)
IGNORE(link)
IGNORE(unlink)
IGNORE(execve)
PROCESS(chdir)
IGNORE(mknod)
IGNORE(chmod)
IGNORE(lchown)
#if defined(__i386__)
PROCESS(oldstat)
#endif
IGNORE(mount)
IGNORE(oldumount)
IGNORE(utime)
#if ! defined(__aarch64__)
PROCESS(access)
#endif
IGNORE(rename)
IGNORE(mkdir)
IGNORE(rmdir)
IGNORE(acct)
IGNORE(umount)
IGNORE(chroot)
IGNORE(symlink)
#if defined(__i386__)
PROCESS(oldlstat)
#endif
#if ! defined(__aarch64__)
PROCESS(readlink)
#endif
IGNORE(uselib)
IGNORE(swapon)
IGNORE(truncate)
IGNORE(statfs)
#if ! defined(__aarch64__)
PROCESS(stat)
PROCESS(lstat)
#endif
IGNORE(chown)
PROCESS(getcwd)
IGNORE(truncate64)
#if defined(__i386__) || defined(__arm__)
PROCESS(stat64)
PROCESS(lstat64)
#endif
IGNORE(lchown32)
IGNORE(chown32)
IGNORE(pivot_root)
IGNORE(setxattr)
IGNORE(lsetxattr)
PROCESS(getxattr)
PROCESS(lgetxattr)
PROCESS(listxattr)
PROCESS(llistxattr)
IGNORE(removexattr)
IGNORE(lremovexattr)
IGNORE(statfs64)
IGNORE(utimes)
PROCESSAT(openat)
IGNORE(mkdirat)
IGNORE(mknodat)
IGNORE(fchownat)
IGNORE(futimesat)
#if defined(__i386__) || defined(__arm__)
PROCESSAT(fstatat64)
#endif
#if defined(__x86_64__) || defined(__aarch64__)
PROCESSAT(newfstatat)
#endif
IGNORE(unlinkat)
IGNORE(renameat)
IGNORE(linkat)
IGNORE(symlinkat)
PROCESSAT(readlinkat)
IGNORE(fchmodat)
PROCESSAT(faccessat)
IGNORE(utimensat)
IGNORE(fallocate)

/* system calls not yet considered */
IGNORE(execveat)
IGNORE(fanotify_mark)
IGNORE(fsconfig)
IGNORE(fspick)
IGNORE(fstat)
IGNORE(fstat64)
IGNORE(fstatfs)
IGNORE(fstatfs64)
IGNORE(inotify_add_watch)
IGNORE(move_mount)
IGNORE(name_to_handle_at)
IGNORE(oldfstat)
IGNORE(open_tree)
IGNORE(quotactl)
IGNORE(renameat2)
IGNORE(statx)
IGNORE(swapoff)
IGNORE(umount2)
IGNORE(utimensat_time64)
IGNORE(newfstat)

/* undefine PROCESS so we can use it again to do something different */
#undef PROCESS
#undef PROCESSAT
