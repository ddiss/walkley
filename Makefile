SUBDIRS := linux/tools/lkl wireguard-tools/src
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
CFLAGS += -pthread -lrt

all: $(SUBDIRS) walkley

clean: $(SUBDIRS)
	$(RM) walkley *.d

walkley: linux/tools/lkl/tests/cla.o linux/tools/lkl/liblkl.a walkley.c

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all clean $(SUBDIRS)
