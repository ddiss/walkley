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
CFLAGS += -I./linux/tools/lkl/tests/
CFLAGS += -I./wireguard-tools/contrib/embeddable-wg-library/
CFLAGS += -pthread
ifneq ($(TARGET), android)
CFLAGS += -lrt
endif

all: $(LKL) walkley

clean: $(LKL)
	$(RM) walkley *.d linux/arch/lkl/configs/walkley_defconfig

linux/tools/lkl/liblkl.a: $(LKL)

linux/tools/lkl/tests/cla.o: $(LKL)

walkley: linux/tools/lkl/tests/cla.o linux/tools/lkl/liblkl.a \
	wireguard-tools/contrib/embeddable-wg-library/wireguard.c walkley.c

linux/arch/lkl/configs/walkley_defconfig: lkl_defconfig
	cp -f $< $@

$(LKL): linux/arch/lkl/configs/walkley_defconfig
	export KCONFIG=walkley_defconfig
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all clean $(LKL)
