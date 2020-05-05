LINUX ?= /lib/modules/`uname -r`/build

obj-m := redir.o

all:
	make -C $(LINUX) M=`pwd` modules

$(obj)/redir.o: $(obj)/need.h $(obj)/wrapper.h

$(obj)/need.h: $(src)/list.h
	$(Q)sed -n '/^#/p; s/^PROCESS\(AT\)\?(\(.*\), .*)$$/#define NEED_\2 1/p' $(src)/list.h > $(obj)/need.h

$(obj)/wrapper.h: $(src)/list.h
	$(Q)sed -n '/^#/p; s/^PROCESS(\(.*\), \(.*\))$$/asmlinkage long orig_\1(char *path,...) { PACK_REGS\2; return x64_orig_\1(\&regs); }/p; s/^PROCESSAT(\(.*\), \(.*\))$$/asmlinkage long orig_\1(int dirfd, char *path,...) { PACK_REGSAT\2; return x64_orig_\1(\&regs); }/p' $(src)/list.h > $(obj)/wrapper.h

install:
	make -C $(LINUX) M=`pwd` modules_install

clean-files := need.h wrapper.h

clean:
	make -C $(LINUX) M=`pwd` clean
