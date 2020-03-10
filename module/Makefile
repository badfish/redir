LINUX ?= /lib/modules/`uname -r`/build

obj-m := redir.o

all:
	make -C $(LINUX) M=`pwd` modules

install:
	make -C $(LINUX) M=`pwd` modules_install

clean:
	make -C $(LINUX) M=`pwd` clean
