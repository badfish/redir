LINUX ?= /lib/modules/`uname -r`/build

obj-m := redir.o

all:
	make -C $(LINUX) CONFIG_STACKPROTECTOR=n CONFIG_STACKPROTECTOR_STRONG=n M=`pwd` modules

$(obj)/redir.o: $(obj)/def32.h $(obj)/need32.h $(obj)/need.h $(obj)/wrapper.h

HOST_EXTRACFLAGS += -I$(LINUX)
hostprogs-y := codegen

$(obj)/def32.h: $(obj)/codegen
	$(obj)/codegen > $(obj)/def32.h

$(obj)/need32.h: $(src)/list.h
	$(Q)sed -n '/^#/p; s/^PROCESS\(AT\)\?(\(.*\), .*)$$/#define NEED_32_\2 1/p' $(src)/list.h > $(obj)/need32.h

$(obj)/need.h: $(src)/list.h
	$(Q)sed -n '/^#/p; s/^PROCESS\(AT\)\?(\(.*\), .*)$$/#define NEED_\2 1/p' $(src)/list.h > $(obj)/need.h

$(obj)/wrapper.h: $(src)/list.h
	$(Q)sed -n '/^#/p; s/^PROCESS(\(.*\), \(.*\))$$/static asmlinkage long orig_\1(char *path,...) { PACK_REGS\2; return wrap_orig_\1(\&regs); }/p; s/^PROCESSAT(\(.*\), \(.*\))$$/asmlinkage long orig_\1(int dirfd, char *path,...) { PACK_REGSAT\2; return wrap_orig_\1(\&regs); }/p' $(src)/list.h > $(obj)/wrapper.h

install:
	make -C $(LINUX) M=`pwd` modules_install

clean-files := def32.h need32.h need.h wrapper.h

clean:
	make -C $(LINUX) M=`pwd` clean
