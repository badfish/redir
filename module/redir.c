#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#if 0
#define DEB(X) printk X
#else
#define DEB(X)
#endif

#define REDIR_VERSION "0.94"

/* copied from fs/fuse/inode.c */
#define FUSE_SUPER_MAGIC 0x65735546
#define AVFS_SUPER_MAGIC FUSE_SUPER_MAGIC

#define AVFS_MAGIC_CHAR '#'
#define OVERLAY_DIR "/.avfs"
#define OVERLAY_DIR_LEN 6

#define PF_AVFS 0x20000000

#define path_ok(pwd) (pwd->d_parent == pwd || !d_unhashed(pwd))

DEFINE_MUTEX(lock);

#if defined(__x86_64__) || defined(__aarch64__)
#define USE_32BIT_COMPAT 1
#include "def32.h"
#endif

#if defined(__x86_64__)
#define USE_64BIT_WRAPPERS 1
#define PARAM1 di
#define PARAM2 si
#define PARAM3 dx
#define PARAM4 r10
#define PARAM1_32 bx
#define PARAM2_32 cx
#define PARAM3_32 dx
#define PARAM4_32 si
#elif defined(__aarch64__)
#define USE_64BIT_WRAPPERS 1
#define PARAM1 regs[0]
#define PARAM2 regs[1]
#define PARAM3 regs[2]
#define PARAM4 regs[3]
#define PARAM1_32 regs[0]
#define PARAM2_32 regs[1]
#define PARAM3_32 regs[2]
#define PARAM4_32 regs[3]
#endif

#if defined(USE_64BIT_WRAPPERS)
typedef asmlinkage long orig_func(char *,...);
typedef asmlinkage long orig_funcat(int dirfd, char *,...);
typedef asmlinkage long (*wrap_orig_func)(struct pt_regs *regs);
#define PROCESS(name, nargs) \
	static wrap_orig_func wrap_orig_##name; \
	static orig_func orig_##name;
#define PROCESSAT(name, nargs) \
	static wrap_orig_func wrap_orig_##name; \
	static orig_funcat orig_##name;
#else
typedef asmlinkage long (*orig_func)(char *,...);
typedef asmlinkage long (*orig_funcat)(int dirfd, char *,...);
#define PROCESS(name, nargs) static orig_func orig_##name;
#define PROCESSAT(name, nargs) static orig_funcat orig_##name;
#endif
#include "list.h"
#include "need.h"

#if defined(USE_32BIT_COMPAT)

#define PROCESS(name, nargs) static wrap_orig_func orig32_##name;
#define PROC_COMPAT_32
#include "list.h"
#include "need.h"

#define PROC_COMPAT_32
#include "need32.h"

static void **ptr_compat32_sys_call_table;

#endif

static void **ptr_sys_call_table;

static char *path_pwd(int dirfd, char *page)
{
	char *ret = 0;
	struct file *file;

	if (dirfd != AT_FDCWD) {
		file = fget(dirfd);
		if (file) {
			ret = d_path(&file->f_path, page, PAGE_SIZE);
			fput(file);
		}
	}
	else
		ret = d_path(&current->fs->pwd, page, PAGE_SIZE);

	return ret;
}

static int a_path_walk(const char *pathname, int flags, struct path *path)
{
	return kern_path(pathname, flags, path);
}

static void a_path_release(struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}

static char *resolv_virt(const char *pathname, int flags)
{
	struct path root;
	struct path ndpath;
	struct path origroot;
	char *newpathname = NULL;
	char *page = NULL;
	char *path = NULL;
	int pathlen = 0;
	int error;
	int newflags;

	mutex_lock(&lock);

	DEB((KERN_INFO "resolve_virt pathname: '%s'\n",
	     pathname ? pathname : "(null)"));

	error = a_path_walk(OVERLAY_DIR, LOOKUP_FOLLOW, &root);
	if (error)
		goto out;

	origroot = current->fs->root;
	current->fs->root = root;

	newflags = flags;

	error  = a_path_walk(pathname, newflags, &ndpath);
	if (!error) {
		if (path_ok(ndpath.dentry)) {
			page = (char *)__get_free_page(GFP_USER);
			if (page) {
				path = d_path(&ndpath, page, PAGE_SIZE);
				DEB((KERN_INFO "resolve_virt path = '%s'\n",
				     path));
				pathlen = (ulong)page + PAGE_SIZE - (ulong)path;
			}
		}
		a_path_release(&ndpath);
	}

	current->fs->root = origroot;

	a_path_release(&root);

	if (path) {
		int isvirtual;

		error  = a_path_walk(path, flags, &ndpath);
		if (!error) {
			if (ndpath.dentry->d_inode)
				isvirtual = 0;
			/*
			else if (must_exist)
				isvirtual = 1;
			else if (strchr(path, AVFS_MAGIC_CHAR))
				isvirtual = 1;
			else
				isvirtual = 0;
			*/
			/* we only implement read-only functions */
			/* so must_exist is always true */
			else
				isvirtual = 1;

			a_path_release(&ndpath);
		}
		else {
			isvirtual = 1;
		}

		if (!isvirtual) {
			newpathname = kmalloc(pathlen + 1, GFP_USER);
			if (newpathname)
				strncpy(newpathname, path, pathlen);
		}
		else {
			newpathname = kmalloc(OVERLAY_DIR_LEN + pathlen + 1,
					      GFP_USER);

			if (newpathname) {
				strcpy(newpathname, OVERLAY_DIR);
				strncat(newpathname, path, pathlen);
			}
		}
	}

	if (page)
		free_page((ulong)page);

	DEB((KERN_INFO "resolve_virt newpathname: '%s'\n",
	     newpathname ? newpathname : "(null)"));

 out:
	mutex_unlock(&lock);
	return newpathname;
}

static int cwd_virtual(int dirfd)
{
	int ret = 0;
	struct file *file;

	if (dirfd != AT_FDCWD) {
		file = fget(dirfd);
		if (file) {
			ret = file->f_path.dentry->d_sb->s_magic == AVFS_SUPER_MAGIC;
			fput(file);
		}
	}
	else
		ret = current->fs->pwd.dentry->d_sb->s_magic == AVFS_SUPER_MAGIC;
	
	return ret;
}

static char *get_abs_path(int dirfd, const char *path)
{
	char *cwd;
	int cwdlen, fnamelen;
	char *abspath, *s;
	char *page;

	if (dirfd==AT_FDCWD && !path_ok(current->fs->pwd.dentry))
		return NULL;

	page = (char *)__get_free_page(GFP_USER);
	if (!page)
		return NULL;

	cwd = path_pwd(dirfd, page);
	cwdlen = (ulong)page + PAGE_SIZE - (ulong)cwd - 1;

	if (cwd_virtual(dirfd) && cwdlen > OVERLAY_DIR_LEN) {
		cwd += OVERLAY_DIR_LEN;
		cwdlen -= OVERLAY_DIR_LEN;
	}

	fnamelen = strlen(path);

	abspath = kmalloc(cwdlen + 1 + fnamelen + 1, GFP_USER);
	if (abspath) {
		s = abspath;
		strncpy(s, cwd, cwdlen);
		s += cwdlen;
		*s++ = '/';
		strncpy(s, path, fnamelen + 1);
	}
	free_page((ulong)page);

	return abspath;
}

static void my_putname(const char *name)
{
	kmem_cache_free(names_cachep, (void *)name);
}

static char *my_getname(const char *filename)
{
	char *result, *err;
	int len;

	result = kmem_cache_alloc(names_cachep, GFP_KERNEL);
	if (!result)
		return ERR_PTR(-ENOMEM);

	len = strncpy_from_user(result, filename, PATH_MAX);

	if (len < 0) {
		err = ERR_PTR(len);
		goto error;
	}

	if (!len) {
		err = ERR_PTR(-ENOENT);
		goto error;
	}

	if (len >= PATH_MAX) {
		err = ERR_PTR(-ENAMETOOLONG);
		goto error;
	}

	return result;

error:
	my_putname(result);
	return err;
}

static char *resolve_name(int dirfd, const char *kfilename, int flags)
{
	char *tmp;
	char *newfilename;

	tmp = my_getname(kfilename);
	if (IS_ERR(tmp))
		return tmp;

	if ((tmp[0] != '/' && cwd_virtual(dirfd)) || strchr(tmp, AVFS_MAGIC_CHAR)) {
		DEB((KERN_INFO "resolve_name: %s (%i/%s)\n", tmp,
		     current->pid,
		     (current->flags & PF_AVFS) ? "on" : "off"));

		if (strcmp(tmp, "/#avfs-on") == 0) {
			printk(KERN_INFO "AVFS ON  (pid: %i)\n",
			       current->pid);
			current->flags |= PF_AVFS;
			newfilename = ERR_PTR(-EEXIST);
		}
		else if (!(current->flags & PF_AVFS))
			newfilename = NULL;
		else if (strcmp(tmp, "/#avfs-off") == 0) {
			printk(KERN_INFO "AVFS OFF (pid: %i)\n",
			       current->pid);
			current->flags &= ~PF_AVFS;
			newfilename = ERR_PTR(-EEXIST);
		}
		else {
			if (tmp[0] == '/') {
				newfilename = resolv_virt(tmp, flags);
			}
			else {
				char *abspath;

				abspath = get_abs_path(dirfd, tmp);
				if (abspath) {
					newfilename = resolv_virt(abspath, flags);
					kfree(abspath);
				}
				else
					newfilename = NULL;
			}
		}
	}
	else
		newfilename = NULL;

	my_putname(tmp);

	return newfilename;
}

typedef long (*do_orig_func)(int dirfd, char *path, void *buf, int param1, long param2);

static asmlinkage long virt_getcwd_common(char *buf, ulong size)
{
	int ret;
	char *cwd;
	ulong cwdlen;
	char *page;
	char *newcwd;
	ulong newlen;

	ret = (*orig_getcwd)(buf, size);

	if (!cwd_virtual(AT_FDCWD) || ret < 0)
		return ret;

	if (!path_ok(current->fs->pwd.dentry))
		return -ENOENT;

	page = (char *)__get_free_page(GFP_USER);
	if (!page)
		return -ENOMEM;

	cwd = path_pwd(AT_FDCWD, page);
	cwdlen = PAGE_SIZE + (page - cwd) - 1;

	if (cwdlen >= OVERLAY_DIR_LEN &&
	   strncmp(cwd, OVERLAY_DIR, OVERLAY_DIR_LEN) == 0) {
		if (cwdlen == OVERLAY_DIR_LEN) {
			newcwd = "/";
			newlen = 1;
		}
		else {
			newcwd = cwd + OVERLAY_DIR_LEN;
			newlen = cwdlen - OVERLAY_DIR_LEN;
		}

		ret = -ERANGE;
		if (newlen + 1 <= size) {
			ret = newlen + 1;
			if (copy_to_user(buf, newcwd, newlen + 1))
				ret = -EFAULT;
		}
	}
	free_page((ulong)page);

	return ret;
}

static long virt_generic(do_orig_func orig, int follow, int dirfd, char *path, void *buf, void *locbuf, int param1, long param2)
{
	long ret;
	mm_segment_t old_fs;
	char *newpath;

	if (task_pid_nr(rcu_dereference(current->real_parent))  == 1) {
		return (*orig)(dirfd, path, buf, param1, param2);
	}

	if (!cwd_virtual(dirfd)) {
		ret = (*orig)(dirfd, path, buf, param1, param2);
		if (ret != -ENOENT)
			return ret;
	}
	else
		ret = 0;

	newpath = resolve_name(dirfd, path, follow);
	if (!newpath) {
		if (ret)
			return ret;
		else
			return (*orig)(dirfd, path, buf, param1, param2);
	}
	if (IS_ERR(newpath))
		return PTR_ERR(newpath);

	if (buf != NULL && locbuf == (void *)-2) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		ret =  (*orig)(dirfd, newpath, buf, param1, param2);
		set_fs(old_fs);
	}
	else if (buf != NULL && locbuf == (void *)-1) {
		if (param1 > PAGE_SIZE)
			param1 = PAGE_SIZE;

		locbuf = (void *)__get_free_page(GFP_USER);
		if (locbuf) {
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			ret =  (*orig)(dirfd, newpath, locbuf, param1, param2);
			set_fs(old_fs);

			if (ret >= 0)
				if (copy_to_user(buf, locbuf, param1))
					ret = -EFAULT;

			free_page((ulong)locbuf);
		}
		else
			ret = -ENOMEM;
	}
	else if (buf == NULL || locbuf != NULL) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		ret =  (*orig)(dirfd, newpath, locbuf, param1, param2);
		set_fs(old_fs);

		if (ret == 0 && locbuf != NULL)
			if (copy_to_user(buf, locbuf, param1))
				ret = -EFAULT;
	}
	else
		ret = 0; /* linux does not have -ENOTSUP */

	kfree(newpath);

	return ret;
}

#if defined(NEED_open)

static long do_orig_open(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_open(path, param1, param2);
}

static asmlinkage long virt_open(char *pathname, int flags, mode_t mode)
{
	return virt_generic(do_orig_open, 1, AT_FDCWD, pathname, NULL, NULL, flags, mode);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_open(struct pt_regs *regs) // (char *pathname, int flags, mode_t mode)
{
	return virt_open((char *)regs->PARAM1, (int)regs->PARAM2, (mode_t)regs->PARAM3);
}
#endif

#endif

#if defined(NEED_chdir)

static long do_orig_chdir(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_chdir(path);
}

static asmlinkage long virt_chdir(char *path)
{
	return virt_generic(do_orig_chdir, 1, AT_FDCWD, path, NULL, NULL, 0, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_chdir(struct pt_regs *regs) // (char *path)
{
	return virt_chdir((char *)regs->PARAM1);
}
#endif

#endif

#if defined(NEED_oldstat)

static long do_orig_oldstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_oldstat(path, buf);
}

static asmlinkage long virt_oldstat(char *path, struct __old_kernel_stat *statbuf)
{
	struct __old_kernel_stat locbuf;
	return virt_generic(do_orig_oldstat, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct __old_kernel_stat), 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_oldstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt_oldstat((char *)regs->PARAM1, (struct __old_kernel_stat *)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_access)

static long do_orig_access(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_access(path, param1);
}

static asmlinkage long virt_access(char *path, int amode)
{
	return virt_generic(do_orig_access, 1, AT_FDCWD, path, NULL, NULL, amode, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_access(struct pt_regs *regs) // (char *path, int amode)
{
	return virt_access((char *)regs->PARAM1, (int)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_oldlstat)

static long do_orig_oldlstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_oldlstat(path, buf);
}

static asmlinkage long virt_oldlstat(char *path, struct __old_kernel_stat *statbuf)
{
	struct __old_kernel_stat locbuf;
	return virt_generic(do_orig_oldlstat, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct __old_kernel_stat), 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_oldlstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt_oldlstat((char *)regs->PARAM1, (struct __old_kernel_stat *)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_readlink)

static long do_orig_readlink(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_readlink(path, buf, param1);
}

static asmlinkage long virt_readlink(char *path, char *buf, int bufsiz)
{
	return virt_generic(do_orig_readlink, 0, AT_FDCWD, path, buf, (void *)-1, bufsiz, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_readlink(struct pt_regs *regs) // (char *path, char *buf, int bufsiz)
{
	return virt_readlink((char *)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3);
}
#endif

#endif

#if defined(NEED_stat)

static long do_orig_stat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_stat(path, buf);
}

static asmlinkage long virt_stat(char *path, struct stat *statbuf)
{
	struct stat locbuf;
	return virt_generic(do_orig_stat, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat), 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_stat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt_stat((char *)regs->PARAM1, (struct stat *)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_lstat)

static long do_orig_lstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lstat(path, buf);
}

static asmlinkage long virt_lstat(char *path, struct stat *statbuf)
{
	struct stat locbuf;
	return virt_generic(do_orig_lstat, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat), 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_lstat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt_lstat((char *)regs->PARAM1, (struct stat *)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_getcwd)

static asmlinkage long virt_getcwd(char *buf, ulong size)
{
	return virt_getcwd_common(buf, size);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_getcwd(struct pt_regs *regs) // (char *buf, ulong size)
{
	return virt_getcwd((char *)regs->PARAM1, (ulong)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_stat64)

static long do_orig_stat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_stat64(path, buf);
}

static asmlinkage long virt_stat64(char *path, struct stat64 *statbuf)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_stat64, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat64), 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_stat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf)
{
	return virt_stat64((char *)regs->PARAM1, (struct stat64 *)regs->PARAM2);
}
#endif

#endif

#if defined(NEED_lstat64)

static long do_orig_lstat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lstat64(path, buf, param2);
}

static asmlinkage long virt_lstat64(char *path, struct stat64 *statbuf, long flags)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_lstat64, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat64), flags);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_lstat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf, long flags)
{
	return virt_lstat64((char *)regs->PARAM1, (struct stat64 *)regs->PARAM2, (long)regs->PARAM3);
}
#endif

#endif

#if defined(NEED_getxattr)

static long do_orig_getxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_getxattr(path, param2, buf, param1);
}

static asmlinkage long virt_getxattr(char *path, char *name, void *value, ulong size)
{
	return virt_generic(do_orig_getxattr, 1, AT_FDCWD, path, value, NULL, size, (long)name);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_getxattr(struct pt_regs *regs) // (char *path, char *name, void *value, ulong size)
{
	return virt_getxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (void *)regs->PARAM3, (ulong)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_lgetxattr)

static long do_orig_lgetxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lgetxattr(path, param2, buf, param1);
}

static asmlinkage long virt_lgetxattr(char *path, char *name, void *value, size_t size)
{
	return virt_generic(do_orig_lgetxattr, 0, AT_FDCWD, path, value, NULL, size, (long)name);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_lgetxattr(struct pt_regs *regs) // (char *path, char *name, void *value, size_t size)
{
	return virt_lgetxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (void *)regs->PARAM3, (size_t)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_listxattr)

static long do_orig_listxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_listxattr(path, buf, param1);
}

static asmlinkage long virt_listxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_listxattr, 1, AT_FDCWD, path, list, NULL, size, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_listxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt_listxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (size_t)regs->PARAM3);
}
#endif

#endif

#if defined(NEED_llistxattr)

static long do_orig_llistxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_llistxattr(path, buf, param1);
}

static asmlinkage long virt_llistxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_llistxattr, 0, AT_FDCWD, path, list, NULL, size, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_llistxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt_llistxattr((char *)regs->PARAM1, (char *)regs->PARAM2, (size_t)regs->PARAM3);
}
#endif

#endif

#if defined(NEED_openat)

static long do_orig_openat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_openat(dirfd, path, param1, param2);
}

static asmlinkage long virt_openat(int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt_generic(do_orig_openat, 1, dirfd, pathname, NULL, NULL, flags, mode);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_openat(struct pt_regs *regs) // (int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt_openat((int)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3, (mode_t)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_fstatat64)

static long do_orig_fstatat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_fstatat64(dirfd, path, buf, param2);
}

static asmlinkage long virt_fstatat64(int dirfd, char *path, struct stat *statbuf, int flag)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_fstatat64, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, statbuf, &locbuf, sizeof(struct stat), flag);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_fstatat64(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt_fstatat64((int)regs->PARAM1, (char *)regs->PARAM2, (struct stat *)regs->PARAM3, (int)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_newfstatat)

static long do_orig_newfstatat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_newfstatat(dirfd, path, buf, param2);
}

static asmlinkage long virt_newfstatat(int dirfd, char *path, struct stat *statbuf, int flag)
{
	struct stat locbuf;
	return virt_generic(do_orig_newfstatat, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, statbuf, &locbuf, sizeof(struct stat), flag);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_newfstatat(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt_newfstatat((int)regs->PARAM1, (char *)regs->PARAM2, (struct stat *)regs->PARAM3, (int)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_readlinkat)

static long do_orig_readlinkat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_readlinkat(dirfd, path, buf, param1);
}

static asmlinkage long virt_readlinkat(int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt_generic(do_orig_readlinkat, 0, dirfd, path, buf, (void *)-1, bufsiz, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_readlinkat(struct pt_regs *regs) // (int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt_readlinkat((int)regs->PARAM1, (char *)regs->PARAM2, (char *)regs->PARAM3, (size_t)regs->PARAM4);
}
#endif

#endif

#if defined(NEED_faccessat)

static long do_orig_faccessat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_faccessat(dirfd, path, param1);
}

static asmlinkage long virt_faccessat(int dirfd, char *pathname, int mode)
{
	return virt_generic(do_orig_faccessat, 1, dirfd, pathname, NULL, NULL, mode, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt_faccessat(struct pt_regs *regs) // (int dirfd, char *pathname, int mode)
{
	return virt_faccessat((int)regs->PARAM1, (char *)regs->PARAM2, (int)regs->PARAM3);
}
#endif

#endif

#if defined(USE_32BIT_COMPAT)

#if defined(NEED_32_open)

static asmlinkage long virt32_open(char *pathname, int flags, mode_t mode)
{
#if defined(__x86_64__)
	return virt_generic(do_orig_open, 1, AT_FDCWD, pathname, NULL, NULL, flags, mode);
#elif defined(__aarch64__)
	return virt_generic(do_orig_openat, 1, AT_FDCWD, pathname, NULL, NULL, flags, mode);
#endif
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_open(struct pt_regs *regs) // (char *pathname, int flags, mode_t mode)
{
	return virt32_open((char *)regs->PARAM1_32, (int)regs->PARAM2_32, (mode_t)regs->PARAM3_32);
}
#endif

#endif

#if defined(NEED_32_chdir)

static asmlinkage long virt32_chdir(char *path)
{
	return virt_generic(do_orig_chdir, 1, AT_FDCWD, path, NULL, NULL, 0, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_chdir(struct pt_regs *regs) // (char *path)
{
	return virt32_chdir((char *)regs->PARAM1_32);
}
#endif

#endif

#if defined(NEED_32_oldstat)

static void cp_stat_to_oldstat(struct stat *s1, char *s2)
{
	*(short *)&s2[0] = s1->st_dev;
	*(short *)&s2[2] = s1->st_ino;
	*(short *)&s2[4] = s1->st_mode;
	*(short *)&s2[6] = s1->st_nlink;
	*(short *)&s2[8] = s1->st_uid;
	*(short *)&s2[10] = s1->st_gid;
	*(short *)&s2[12] = s1->st_rdev;
	*(int *)&s2[16] = s1->st_size;
	*(int *)&s2[20] = s1->st_atime;
	*(int *)&s2[24] = s1->st_mtime;
	*(int *)&s2[28] = s1->st_ctime;
}

static asmlinkage long virt32_oldstat(char *path, char *statbuf)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_stat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_oldstat(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_oldstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt32_oldstat((char *)regs->PARAM1_32, (char *)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_access)

static asmlinkage long virt32_access(char *path, int amode)
{
#if defined(__x86_64__)
	return virt_generic(do_orig_access, 1, AT_FDCWD, path, NULL, NULL, amode, 0);
#elif defined(__aarch64__)
	return virt_generic(do_orig_faccessat, 1, AT_FDCWD, path, NULL, NULL, amode, 0);
#endif
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_access(struct pt_regs *regs) // (char *path, int amode)
{
	return virt32_access((char *)regs->PARAM1_32, (int)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_oldlstat)

static asmlinkage long virt32_oldlstat(char *path, char *statbuf)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_lstat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), AT_SYMLINK_NOFOLLOW);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_oldstat(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_oldlstat(struct pt_regs *regs) // (char *path, struct __old_kernel_stat *statbuf)
{
	return virt32_oldlstat((char *)regs->PARAM1_32, (char *)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_readlink)

static asmlinkage long virt32_readlink(char *path, char *buf, int bufsiz)
{
#if defined(__x86_64__)
	return virt_generic(do_orig_readlink, 0, AT_FDCWD, path, buf, (void *)-1, bufsiz, 0);
#elif defined(__aarch64__)
	return virt_generic(do_orig_readlinkat, 0, AT_FDCWD, path, buf, (void *)-1, bufsiz, 0);
#endif
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_readlink(struct pt_regs *regs) // (char *path, char *buf, int bufsiz)
{
	return virt32_readlink((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (int)regs->PARAM3_32);
}
#endif

#endif

#if defined(NEED_32_stat)

static void cp_stat_to_stat(struct stat *s1, char *s2)
{
	*(int *)&s2[0] = s1->st_dev;
	*(int *)&s2[4] = s1->st_ino;
	*(short *)&s2[8] = s1->st_mode;
	*(short *)&s2[10] = s1->st_nlink;
	*(short *)&s2[12] = s1->st_uid;
	*(short *)&s2[14] = s1->st_gid;
	*(int *)&s2[16] = s1->st_rdev;
	*(int *)&s2[20] = s1->st_size;
	*(int *)&s2[24] = s1->st_blksize;
	*(int *)&s2[28] = s1->st_blocks;
	*(long *)&s2[32] = s1->st_atime;
	*(long *)&s2[40] = s1->st_mtime;
	*(long *)&s2[48] = s1->st_ctime;
}

static asmlinkage long virt32_stat(char *path, char *statbuf)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_stat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_stat(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_stat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt32_stat((char *)regs->PARAM1_32, (char *)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_lstat)

static asmlinkage long virt32_lstat(char *path, char *statbuf)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_lstat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), AT_SYMLINK_NOFOLLOW);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_stat(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_lstat(struct pt_regs *regs) // (char *path, struct stat *statbuf)
{
	return virt32_lstat((char *)regs->PARAM1_32, (char *)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_getcwd)

static asmlinkage long virt32_getcwd(char *buf, ulong size)
{
	return virt_getcwd_common(buf, size);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_getcwd(struct pt_regs *regs) // (char *buf, ulong size)
{
	return virt32_getcwd((char *)regs->PARAM1_32, (ulong)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_stat64)

static void cp_stat_to_stat64(struct stat *s1, char *s2)
{
	*(long *)&s2[0] = s1->st_dev;
	*(int *)&s2[8] = 0;
	*(int *)&s2[12] = s1->st_ino;
	*(int *)&s2[16] = s1->st_mode;
	*(long *)&s2[20] = s1->st_nlink;
	*(int *)&s2[24] = s1->st_uid;
	*(int *)&s2[28] = s1->st_gid;
	*(long *)&s2[32] = s1->st_rdev;
#if defined(__x86_64__)
	*(long *)&s2[44] = s1->st_size;
	*(long *)&s2[52] = s1->st_blksize;
	*(long *)&s2[56] = s1->st_blocks;
	*(long *)&s2[64] = s1->st_atime;
	*(long *)&s2[72] = s1->st_mtime;
	*(long *)&s2[80] = s1->st_ctime;
	*(long *)&s2[88] = s1->st_ino;
#elif defined(__aarch64__)
	*(long *)&s2[48] = s1->st_size;
	*(long *)&s2[56] = s1->st_blksize;
	*(long *)&s2[64] = s1->st_blocks;
	*(long *)&s2[72] = s1->st_atime;
	*(long *)&s2[80] = s1->st_mtime;
	*(long *)&s2[88] = s1->st_ctime;
	*(long *)&s2[96] = s1->st_ino;
#else
#error "Architecture not implemented"
#endif
}

static asmlinkage long virt32_stat64(char *path, char *statbuf)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_stat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 1, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_stat64(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_stat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf)
{
	return virt32_stat64((char *)regs->PARAM1_32, (char *)regs->PARAM2_32);
}
#endif

#endif

#if defined(NEED_32_lstat64)

static asmlinkage long virt32_lstat64(char *path, char *statbuf, long flags)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if defined(__x86_64__)
	ret = virt_generic(do_orig_lstat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), 0);
#elif defined(__aarch64__)
	ret = virt_generic(do_orig_newfstatat, 0, AT_FDCWD, path, &s, (void *)-2, sizeof(s), AT_SYMLINK_NOFOLLOW);
#endif
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_stat64(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_lstat64(struct pt_regs *regs) // (char *path, struct stat64 *statbuf, long flags)
{
	return virt32_lstat64((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (long)regs->PARAM3_32);
}
#endif

#endif

#if defined(NEED_32_getxattr)

static asmlinkage long virt32_getxattr(char *path, char *name, void *value, ulong size)
{
	return virt_generic(do_orig_getxattr, 1, AT_FDCWD, path, value, NULL, size, (long)name);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_getxattr(struct pt_regs *regs) // (char *path, char *name, void *value, ulong size)
{
	return virt32_getxattr((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (void *)regs->PARAM3_32, (ulong)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_lgetxattr)

static asmlinkage long virt32_lgetxattr(char *path, char *name, void *value, size_t size)
{
	return virt_generic(do_orig_lgetxattr, 0, AT_FDCWD, path, value, NULL, size, (long)name);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_lgetxattr(struct pt_regs *regs) // (char *path, char *name, void *value, size_t size)
{
	return virt32_lgetxattr((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (void *)regs->PARAM3_32, (size_t)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_listxattr)

static asmlinkage long virt32_listxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_listxattr, 1, AT_FDCWD, path, list, NULL, size, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_listxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt32_listxattr((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (size_t)regs->PARAM3_32);
}
#endif

#endif

#if defined(NEED_32_llistxattr)

static asmlinkage long virt32_llistxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_llistxattr, 0, AT_FDCWD, path, list, NULL, size, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_llistxattr(struct pt_regs *regs) // (char *path, char *list, size_t size)
{
	return virt32_llistxattr((char *)regs->PARAM1_32, (char *)regs->PARAM2_32, (size_t)regs->PARAM3_32);
}
#endif

#endif

#if defined(NEED_32_openat)

static asmlinkage long virt32_openat(int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt_generic(do_orig_openat, 1, dirfd, pathname, NULL, NULL, flags, mode);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_openat(struct pt_regs *regs) // (int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt32_openat((int)regs->PARAM1_32, (char *)regs->PARAM2_32, (int)regs->PARAM3_32, (mode_t)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_fstatat64)

static asmlinkage long virt32_fstatat64(int dirfd, char *path, char *statbuf, int flag)
{
	long ret;
	struct stat s;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = virt_generic(do_orig_newfstatat, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, &s, (void *)-2, sizeof(s), flag);
	set_fs(old_fs);
	if (ret == 0)
		cp_stat_to_stat64(&s, statbuf);
	return ret;
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_fstatat64(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt32_fstatat64((int)regs->PARAM1_32, (char *)regs->PARAM2_32, (char *)regs->PARAM3_32, (int)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_newfstatat)

static asmlinkage long virt32_newfstatat(int dirfd, char *path, struct stat *statbuf, int flag)
{
	struct stat locbuf;
	return virt_generic(do_orig_newfstatat, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, statbuf, &locbuf, sizeof(struct stat), flag);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_newfstatat(struct pt_regs *regs) // (int dirfd, char *path, struct stat *statbuf, int flag)
{
	return virt32_newfstatat((int)regs->PARAM1_32, (char *)regs->PARAM2_32, (struct stat *)regs->PARAM3_32, (int)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_readlinkat)

static asmlinkage long virt32_readlinkat(int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt_generic(do_orig_readlinkat, 0, dirfd, path, buf, (void *)-1, bufsiz, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_readlinkat(struct pt_regs *regs) // (int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt32_readlinkat((int)regs->PARAM1_32, (char *)regs->PARAM2_32, (char *)regs->PARAM3_32, (size_t)regs->PARAM4_32);
}
#endif

#endif

#if defined(NEED_32_faccessat)

static asmlinkage long virt32_faccessat(int dirfd, char *pathname, int mode)
{
	return virt_generic(do_orig_faccessat, 1, dirfd, pathname, NULL, NULL, mode, 0);
}

#if defined(USE_64BIT_WRAPPERS)
static asmlinkage long wrap_virt32_faccessat(struct pt_regs *regs) // (int dirfd, char *pathname, int mode)
{
	return virt32_faccessat((int)regs->PARAM1_32, (char *)regs->PARAM2_32, (int)regs->PARAM3_32);
}
#endif

#endif

#endif

#if defined(USE_64BIT_WRAPPERS)

#define PACK_REGS1 \
	struct pt_regs regs; \
	regs.PARAM1 = (ulong)path

#define PACK_REGS2 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	va_end(ap)

#define PACK_REGS3 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	regs.PARAM3 = va_arg(ap, ulong); \
	va_end(ap)

#define PACK_REGS4 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)path; \
	regs.PARAM2 = va_arg(ap, ulong); \
	regs.PARAM3 = va_arg(ap, ulong); \
	regs.PARAM4 = va_arg(ap, ulong); \
	va_end(ap)

#define PACK_REGSAT3 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)dirfd; \
	regs.PARAM2 = (ulong)path; \
	regs.PARAM3 = va_arg(ap, ulong); \
	va_end(ap)

#define PACK_REGSAT4 \
	struct pt_regs regs; \
	va_list ap; \
	va_start(ap, path); \
	regs.PARAM1 = (ulong)dirfd; \
	regs.PARAM2 = (ulong)path; \
	regs.PARAM3 = va_arg(ap, ulong); \
	regs.PARAM4 = va_arg(ap, ulong); \
	va_end(ap)

#include "wrapper.h"

#endif

#if defined(__i386__) || defined(__x86_64__)

static int set_syscall_entry(void **address, void *value)
{
	pte_t old_pte, *kpte;
	unsigned int level;

	kpte = lookup_address((ulong)address, &level);
	if (!kpte) {
		printk(KERN_ERR "No page table entry for system call table\n");
		return -EINVAL;
	}

	old_pte = *kpte; 
	if (!pte_val(old_pte) || !pte_present(old_pte)) {
		printk(KERN_ERR "Bad page table entry for system call table\n");
		return -EINVAL;
	}

	if (pte_write(old_pte)) {
		*address = value;
	}
	else {
		pgprot_t new_prot = pte_pgprot(old_pte);
		ulong pfn = pte_pfn(old_pte);   
		pte_t new_pte;

		pgprot_val(new_prot) |= _PAGE_RW;

		new_pte = pfn_pte(pfn, canon_pgprot(new_prot));
		set_pte_atomic(kpte, new_pte);

		*address = value;

		set_pte_atomic(kpte, old_pte);
	}
	return 0;
}

#elif defined(__arm__)

static int set_syscall_entry(void **address, void *value)
{
	ulong start = (ulong)address & PAGE_MASK;
	ulong end = start + PAGE_SIZE;

	static void (*ptr_set_kernel_text_rw)(void);
	static void (*ptr_set_kernel_text_ro)(void);
	static void (*ptr_v7wbi_flush_kern_tlb_range)(ulong start, ulong end);

	if (ptr_set_kernel_text_rw == 0) {
		ptr_set_kernel_text_rw = (void(*)(void))kallsyms_lookup_name("set_kernel_text_rw");
		ptr_set_kernel_text_ro = (void(*)(void))kallsyms_lookup_name("set_kernel_text_ro");
		ptr_v7wbi_flush_kern_tlb_range =
			(void (*)(ulong,ulong))kallsyms_lookup_name("v7wbi_flush_kern_tlb_range");
	}

	if (ptr_set_kernel_text_rw == 0 || ptr_set_kernel_text_ro == 0) {
		printk(KERN_ERR "Cannot find functions to set text rw/ro\n");
		return -EINVAL;
	}

	ptr_set_kernel_text_rw();
	ptr_v7wbi_flush_kern_tlb_range(start, end);
	*address = value;
	ptr_set_kernel_text_ro();
	ptr_v7wbi_flush_kern_tlb_range(start, end);

	return 0;
}

#elif defined(__aarch64__)

static int set_syscall_entry(void **address, void *value)
{
	/* none of the following is actually needed on my test system as the */
	/* sys call table is not ro; hence it is not clear whether it works */
	/* it *should* work for 32-bit arm, but it doesn't for unknown reason */
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	pte_t old_pte;

	static struct mm_struct *ptr_init_mm = 0;

	if (ptr_init_mm == 0) {
		ptr_init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	}

	if (ptr_init_mm == 0) {
		printk(KERN_ERR "Cannot find init_mm\n");
		return -EINVAL;
	}

	pgd = pgd_offset(ptr_init_mm, (ulong)address);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		printk(KERN_ERR "Bad pgd when replacing system call\n");
		return -EINVAL;
	}
	pud = pud_offset(pgd, (ulong)address);
	if (pud_none(*pud) || pud_bad(*pud)) {
		printk(KERN_ERR "Bad pud when replacing system call\n");
		return -EINVAL;
	}
	pmd = pmd_offset(pud, (ulong)address);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		printk(KERN_ERR "Bad pmd when replacing system call\n");
		return -EINVAL;
	}
	ptep = pte_offset_map(pmd, (ulong)address);
	if (!ptep) {
		printk(KERN_ERR "Bad pte when replacing system call\n");
		return -EINVAL;
	}

	old_pte = *ptep;
	*ptep = pte_mkwrite(*ptep);
	flush_tlb_all();

	*address = value;

	*ptep = old_pte;
	flush_tlb_all();

	return 0;
}

#else
#error "Architecture not implemented"
#endif

static void *replace_syscall(void **table, int index, void *new_syscall)
{
	void *orig_syscall = table[index];

	printk(KERN_INFO "Replacing syscall nr. %3i [%lx] with [%lx]\n",
	       index, (ulong)orig_syscall, (ulong)new_syscall);
	set_syscall_entry(&table[index], new_syscall);

	return orig_syscall;
}

static int find_addresses(void)
{
	long ptr_sys_close;

	ptr_sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	if (ptr_sys_call_table == (void **)0) {
		printk(KERN_ERR "Lookup of sys_call_table failed\n");
		return -EINVAL;
	}

	/* sanity check*/
#if defined(__i386__)
	ptr_sys_close = kallsyms_lookup_name("sys_close");
#elif defined(__x86_64__)
	ptr_sys_close = kallsyms_lookup_name("__x64_sys_close");
#elif defined(__arm__)
	ptr_sys_close = kallsyms_lookup_name("sys_close");
#elif defined(__aarch64__)
	ptr_sys_close = kallsyms_lookup_name("__arm64_sys_close");
#else
#error "Architecture not implemented"
#endif

	if (ptr_sys_close == 0L || ptr_sys_call_table[__NR_close] != (void *)ptr_sys_close) {
		printk(KERN_ERR "Sanity check failed: expected %lx got %lx\n",
			(ulong)ptr_sys_call_table[__NR_close], ptr_sys_close);
		return -EINVAL;
	}

#if defined(USE_32BIT_COMPAT)
#if defined(__x86_64__)
	ptr_compat32_sys_call_table = (void **)kallsyms_lookup_name("ia32_sys_call_table");
#elif defined(__aarch64__)
	ptr_compat32_sys_call_table = (void **)kallsyms_lookup_name("compat_sys_call_table");
#else
#error "Architecture not implemented"
#endif
	if (ptr_compat32_sys_call_table == (void **)0) {
		printk(KERN_ERR "Lookup of sys_call_table failed\n");
		return -EINVAL;
	}

#if defined(__x86_64__)
	ptr_sys_close = kallsyms_lookup_name("__ia32_sys_close");
#elif defined(__aarch64__)
	ptr_sys_close = kallsyms_lookup_name("__arm64_sys_close");
#else
#error "Architecture not implemented"
#endif
	if (ptr_sys_close == 0L || ptr_compat32_sys_call_table[__NR_32_close] != (void *)ptr_sys_close) {
		printk(KERN_ERR "Sanity check failed: expected %lx got %lx\n",
			(ulong)ptr_compat32_sys_call_table[__NR_32_close], ptr_sys_close);
		return -EINVAL;
	}
#endif

	return 0;
}

int init_module(void)
{
	int ret;

	printk(KERN_INFO "Redir init (version %s)\n", REDIR_VERSION);

	mutex_init(&lock);
	ret = find_addresses();
	if (ret)
		return ret;

#if defined(USE_64BIT_WRAPPERS)
#define PROCESS(name, nargs) \
	wrap_orig_##name = replace_syscall(ptr_sys_call_table, __NR_##name, wrap_virt_##name);
#else
#define PROCESS(name, nargs) \
	orig_##name = replace_syscall(ptr_sys_call_table, __NR_##name, virt_##name);
#endif
#include "list.h"

#if defined(USE_32BIT_COMPAT)
#if defined(USE_64BIT_WRAPPERS)
#define PROCESS(name, nargs) \
	orig32_##name = replace_syscall(ptr_compat32_sys_call_table, __NR_32_##name, wrap_virt32_##name);
#else
#define PROCESS(name, nargs) \
	orig32_##name = replace_syscall(ptr_compat32_sys_call_table, __NR_32_##name, virt32_##name);
#endif
#define PROC_COMPAT_32
#include "list.h"
#endif

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Redir cleanup\n");

#if defined (USE_64BIT_WRAPPERS)
#define PROCESS(name, nargs) \
	replace_syscall(ptr_sys_call_table, __NR_##name, wrap_orig_##name);
#else
#define PROCESS(name, nargs) \
	replace_syscall(ptr_sys_call_table, __NR_##name, orig_##name);
#endif
#include "list.h"

#if defined(USE_32BIT_COMPAT)
#define PROCESS(name, nargs) \
	replace_syscall(ptr_compat32_sys_call_table, __NR_32_##name, orig32_##name);
#define PROC_COMPAT_32
#include "list.h"
#endif

	mutex_destroy(&lock);
}
