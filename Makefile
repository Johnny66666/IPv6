obj-m += sch_red.o
KERNELBUILD := /lib/modules/`uname -r`/build
all:
	make -C $(KERNELBUILD) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.c .tmp_versions modules* Module*
