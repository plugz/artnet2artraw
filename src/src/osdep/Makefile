AC_ROOT	= ../..
include $(AC_ROOT)/common.mak

LIB		= libosdep.a
CFLAGS		+= $(PIC) -I..

OBJS_COMMON	= network.o file.o
OBJS		= osdep.o $(OBJS_COMMON)

OBJS_LINUX	= $(OBJS) linux.o linux_tap.o radiotap/radiotap.o common.o

all:
	@echo Building for $(OSNAME)
	@$(MAKE) .os.$(OSNAME)

.os.Linux: $(OBJS_LINUX)
	$(AR) cru $(LIB) $(OBJS_LINUX)
	$(RANLIB) $(LIB)
	touch $(@)

.os.%:
	@echo "Your platform is unsupported by osdep"
	touch $(@)
