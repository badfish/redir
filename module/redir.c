#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <asm/uaccess.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <asm/pgtable.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>

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

#if defined(__x86_64__) || defined(__aarch64__)
typedef asmlinkage long orig_func(char *,...);
typedef asmlinkage long orig_funcat(int dirfd, char *,...);
typedef asmlinkage long (*x64_orig_func)(struct pt_regs *regs);
#define PROCESS(name) \
	static x64_orig_func x64_orig_##name; \
	static orig_func orig_##name;
#define PROCESSAT(name) \
	static x64_orig_func x64_orig_##name; \
	static orig_funcat orig_##name;
#else
typedef asmlinkage long (*orig_func)(char *,...);
typedef asmlinkage long (*orig_funcat)(int dirfd, char *,...);
#define PROCESS(name) static orig_func orig_##name;
#define PROCESSAT(name) static orig_funcat orig_##name;
#endif
#include "list.h"

#define AVFS_MAGIC_CHAR '#'
#define OVERLAY_DIR "/.avfs"
#define OVERLAY_DIR_LEN 6

#define PF_AVFS 0x20000000

#define path_ok(pwd) (pwd->d_parent == pwd || !d_unhashed(pwd))

DEFINE_MUTEX(lock);

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

static long virt_generic(do_orig_func orig, int follow, int dirfd, char *path, void *buf, void *locbuf, int param1, long param2)
{
	long ret;
	mm_segment_t old_fs;
	char *newpath;

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

	if (buf != NULL && locbuf == (void *)-1) {
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

#if ! defined(__aarch64__)

static long do_orig_open(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_open(path, param1, param2);
}

asmlinkage long virt_open(char *pathname, int flags, mode_t mode)
{
	return virt_generic(do_orig_open, 1, AT_FDCWD, pathname, NULL, NULL, flags, mode);
}

#endif

static long do_orig_chdir(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_chdir(path);
}

asmlinkage long virt_chdir(char *path)
{
	return virt_generic(do_orig_chdir, 1, AT_FDCWD, path, NULL, NULL, 0, 0);
}

#if defined(__i386__)

static long do_orig_oldstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_oldstat(path, buf);
}

asmlinkage long virt_oldstat(char *path, struct __old_kernel_stat *statbuf)
{
	struct __old_kernel_stat locbuf;
	return virt_generic(do_orig_oldstat, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct __old_kernel_stat), 0);
}

#endif

#if ! defined(__aarch64__)

static long do_orig_access(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_access(path, param1);
}

asmlinkage long virt_access(char *path, int amode)
{
	return virt_generic(do_orig_access, 1, AT_FDCWD, path, NULL, NULL, amode, 0);
}

#endif

#if defined(__i386__)

static long do_orig_oldlstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_oldlstat(path, buf);
}

asmlinkage long virt_oldlstat(char *path, struct __old_kernel_stat *statbuf)
{
	struct __old_kernel_stat locbuf;
	return virt_generic(do_orig_oldlstat, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct __old_kernel_stat), 0);
}

#endif

#if ! defined(__aarch64__)

static long do_orig_readlink(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_readlink(path, buf, param1);
}

asmlinkage long virt_readlink(char *path, char *buf, int bufsiz)
{
	return virt_generic(do_orig_readlink, 0, AT_FDCWD, path, buf, (void *)-1, bufsiz, 0);
}

static long do_orig_stat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_stat(path, buf);
}

asmlinkage long virt_stat(char *path, struct stat *statbuf)
{
	struct stat locbuf;
	return virt_generic(do_orig_stat, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat), 0);
}

static long do_orig_lstat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lstat(path, buf);
}

asmlinkage long virt_lstat(char *path, struct stat *statbuf)
{
	struct stat locbuf;
	return virt_generic(do_orig_lstat, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat), 0);
}

#endif

asmlinkage long virt_getcwd(char *buf, ulong size)
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

#if defined(__i386__) || defined(__arm__)

static long do_orig_stat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_stat64(path, buf);
}

asmlinkage long virt_stat64(char *path, struct stat64 *statbuf)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_stat64, 1, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat64), 0);
}

static long do_orig_lstat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lstat64(path, buf, param2);
}

asmlinkage long virt_lstat64(char *path, struct stat64 *statbuf, long flags)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_lstat64, 0, AT_FDCWD, path, statbuf, &locbuf, sizeof(struct stat64), flags);
}

#endif

static long do_orig_getxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_getxattr(path, param2, buf, param1);
}

asmlinkage long virt_getxattr(char *path, char *name, void *value, ulong size)
{
	return virt_generic(do_orig_getxattr, 1, AT_FDCWD, path, value, NULL, size, (long)name);
}

static long do_orig_lgetxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_lgetxattr(path, param2, buf, param1);
}

asmlinkage long virt_lgetxattr(char *path, char *name, void *value, size_t size)
{
	return virt_generic(do_orig_lgetxattr, 0, AT_FDCWD, path, value, NULL, size, (long)name);
}

static long do_orig_listxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_listxattr(path, buf, param1);
}

asmlinkage long virt_listxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_listxattr, 1, AT_FDCWD, path, list, NULL, size, 0);
}

static long do_orig_llistxattr(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_llistxattr(path, buf, param1);
}

asmlinkage long virt_llistxattr(char *path, char *list, size_t size)
{
	return virt_generic(do_orig_llistxattr, 0, AT_FDCWD, path, list, NULL, size, 0);
}

static long do_orig_openat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_openat(dirfd, path, param1, param2);
}

asmlinkage long virt_openat(int dirfd, char *pathname, int flags, mode_t mode)
{
	return virt_generic(do_orig_openat, 1, dirfd, pathname, NULL, NULL, flags, mode);
}

#if defined(__i386__) || defined(__arm__)

static long do_orig_fstatat64(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_fstatat64(dirfd, path, buf, param2);
}

asmlinkage long virt_fstatat64(int dirfd, char *path, struct stat *statbuf, int flag)
{
	struct stat64 locbuf;
	return virt_generic(do_orig_fstatat64, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, statbuf, &locbuf, sizeof(struct stat), flag);
}

#endif

#if defined(__x86_64__) || defined(__aarch64__)

static long do_orig_newfstatat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_newfstatat(dirfd, path, buf, param2);
}

asmlinkage long virt_newfstatat(int dirfd, char *path, struct stat *statbuf, int flag)
{
	struct stat locbuf;
	return virt_generic(do_orig_newfstatat, (flag & AT_SYMLINK_NOFOLLOW)==0, dirfd, path, statbuf, &locbuf, sizeof(struct stat), flag);
}

#endif

static long do_orig_readlinkat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_readlinkat(dirfd, path, buf, param1);
}

asmlinkage long virt_readlinkat(int dirfd, char *path, char *buf, size_t bufsiz)
{
	return virt_generic(do_orig_readlinkat, 0, dirfd, path, buf, (void *)-1, bufsiz, 0);
}

static long do_orig_faccessat(int dirfd, char *path, void *buf, int param1, long param2)
{
	return orig_faccessat(dirfd, path, param1);
}

asmlinkage long virt_faccessat(int dirfd, char *pathname, int mode)
{
	return virt_generic(do_orig_faccessat, 1, dirfd, pathname, NULL, NULL, mode, 0);
}

#if defined(__x86_64__) || defined(__aarch64__)
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

void *replace_syscall(int index, void *new_syscall)
{
	void *orig_syscall = ptr_sys_call_table[index];

	printk(KERN_INFO "Replacing syscall nr. %3i [%lx] with [%lx]\n",
	       index, (ulong)orig_syscall, (ulong)new_syscall);
	set_syscall_entry(&ptr_sys_call_table[index], new_syscall);

	return orig_syscall;
}

static void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len)
{
	const char *begin;
	const char *const last_possible = (const char *)haystack + haystack_len - needle_len;

	if (needle_len == 0)
		return (void *)haystack;

	if (__builtin_expect(haystack_len < needle_len, 0))
		return NULL;

	for (begin = (const char *)haystack; begin <= last_possible; ++begin)
		if (begin[0] == ((const char *)needle)[0] && !memcmp(begin, needle, needle_len))
			return (void *)begin;

	return NULL;
}

#if defined(__i386__)

static int get_syscall_table(void)
{
	ulong system_call;
	unsigned char *ptr;

#if 0 // this code worked when the int 80 handler was assembly code

	struct {
		unsigned short limit;
		ulong base;
	} __attribute__ ((packed)) idtr;

	struct {
		unsigned short offset1;
		unsigned short segment;   
		unsigned char none, flags;
		unsigned short offset2;
	} __attribute__ ((packed)) idt;

	/* read IDTR */
	asm("sidt %0" : "=m" (idtr));
	printk(KERN_INFO "IDTR base at %lx\n", idtr.base);

	/* read in IDT for vector 0x80 (syscall) */ 
	memcpy(&idt, (char *)idtr.base + 8 * 0x80, sizeof(idt)); 
	system_call = (idt.offset2 << 16) | idt.offset1;
	printk(KERN_INFO "System_call at %lx\n", system_call);

	/* look for 'call *sys_call_table(,%eax,4)' */
	ptr = memmem((void *)system_call, 160, "\xff\x14\x85", 3);

#else // this code works in kernel 4.19 with int 80 handler in arch/x86/entry/common.c

	system_call = kallsyms_lookup_name("do_int80_syscall_32");
	if (system_call == 0L) {
		printk(KERN_ERR "Cannot find system_call\n");
		return -1;
	}

	/* look for 'mov sys_call_table(,%eax,4),%eax' */
	ptr = memmem((void *)system_call, 160, "\x8b\x04\x85", 3);

#endif

	if (ptr == NULL) {
		printk(KERN_ERR "Cannot find sys_call_table following system_call\n");
		return -1;
	}

	/* instruction contains 4-byte address */
	ptr_sys_call_table = *(void ***)(ptr + 3);
	printk(KERN_INFO "Found address of sys_call_table %lx at %lx\n",
		(ulong)ptr_sys_call_table, (ulong)ptr);

	return 0;
}

#elif defined(__x86_64__)

static int get_syscall_table(void)
{
	ulong system_call;
	unsigned char *ptr;
	int32_t addr;

#if 0 // this code worked when the sys call handler was assembly code

	rdmsrl(MSR_LSTAR, system_call);
	printk(KERN_INFO "System_call is at %lx\n", system_call);

	/* look for 'call *sys_call_table(,%rax,8)' */
	ptr = memmem((void *)system_call, 240, "\xff\x14\xc5", 3);

#else // this code works in kernel 4.19 with sys call handler in arch/x86/entry/common.c

	system_call = kallsyms_lookup_name("do_syscall_64");
	if (system_call == 0L) {
		printk(KERN_ERR "Cannot find system_call\n");
		return -1;
	}

	/* look for 'movq sys_call_table(,%rax,8),%rax' */
	ptr = memmem((void *)system_call, 160, "\x8b\x04\xc5", 3);

#endif

	if (ptr == NULL) {
		printk(KERN_ERR "Cannot find sys_call_table following system_call\n");
		return -1;
	}

	/* instruction contains 4-byte signed address */
	addr = *(int32_t *)(ptr + 3);
	ptr_sys_call_table = (void **)((ulong)addr);

	return 0;
}

#elif defined(__arm__)

static int get_syscall_table(void)
{
	ulong addr = 0xffff0008;
	ulong word;

	word = *(ulong *)addr;
	printk(KERN_INFO "SWI instruction is %lx\n", word);

	/* software interrupt location at 0xffff0008 */
	/* should contain instruction 'LDR PC,offset' (e59ffxxx) */
	if ((word & 0xfffff000) != 0xe59ff000) {
		printk(KERN_ERR "Cannot find LDR instruction at SWI address\n");
		return -1;
	}

	/* this address contains the next address which is loaded into the PC */
	addr += (word & 0xfff) + 8;
	word = *(ulong *)addr;
	printk(KERN_INFO "SWI jump to address %lx\n", word);

	/* look for instruction 'ADR Rn,sys_call_table' (e28fxxxx) */
	addr = (ulong)memmem((void *)word, 128, "\x8f\xe2", 2);
	if (addr == (ulong)NULL) {
		printk(KERN_ERR "Cannot find sys_call_table following system_call\n");
		return -1;
	}

	/* instruction is stored little-endian */
	addr -= 2;
	if ((addr & 0x03) != 0) {
		printk(KERN_ERR "Did not find instruction address: not aligned\n");
		return -1;
	}
	word = *(ulong *)addr;
	addr += (word & 0xfff) + 8;

	ptr_sys_call_table = (void **)addr;
	return 0;
}

#elif defined(__aarch64__)

static int get_syscall_table(void)
{
	/* decoding aarch64 instructions is horrible */
	/* so we're just not going to attempt it */
	return -1;
}

#else
#error "Architecture not implemented"
#endif

int find_addresses(void)
{
	long ptr_sys_close;

	ptr_sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	if (ptr_sys_call_table == (void **)0) {
		printk(KERN_ERR "Lookup of sys_call_table failed\n");
		if (get_syscall_table())
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

#if defined(__x86_64__) || defined(__aarch64__)
#define PROCESS(name) \
	x64_orig_##name = replace_syscall(__NR_##name, x64_virt_##name);
#else
#define PROCESS(name) \
	orig_##name = replace_syscall(__NR_##name, virt_##name);
#endif
#include "list.h"

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Redir cleanup\n");

#if defined (__x86_64__) || defined(__aarch64__)
#define PROCESS(name) \
	replace_syscall(__NR_##name, x64_orig_##name);
#else
#define PROCESS(name) \
	replace_syscall(__NR_##name, orig_##name);
#endif
#include "list.h"

	mutex_destroy(&lock);
}
