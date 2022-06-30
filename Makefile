# The kernel config below will be copied under linux/arch/lkl/configs/
# and used for lkl compilation.
LKL_CONFIG := lkl_defconfig
LKL := linux/tools/lkl

CFLAGS ?= -O3
CFLAGS += -idirafter uapi
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra
CFLAGS += -MMD -MP
ifeq ($(DEBUG),yes)
CFLAGS += -g
endif
CFLAGS += -I./linux/tools/lkl/include/
CFLAGS += -I./wireguard-tools/contrib/embeddable-wg-library/
CFLAGS += -pthread
ifneq ($(TARGET), android)
CFLAGS += -lrt
endif

all: $(LKL) walkley

clean: $(LKL)
	$(RM) walkley *.d linux/arch/lkl/configs/walkley_defconfig

linux/tools/lkl/liblkl.a: $(LKL)

walkley: linux/tools/lkl/liblkl.a \
	wireguard-tools/contrib/embeddable-wg-library/wireguard.c \
	vendor/cl_arg.c \
	vendor/dbg.c \
	walkley.c

linux/arch/lkl/configs/walkley_defconfig: $(LKL_CONFIG)
	cp -f $< $@

$(LKL): linux/arch/lkl/configs/walkley_defconfig
	export KCONFIG=walkley_defconfig
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all clean $(LKL)
