AC_ROOT		= ..
include $(AC_ROOT)/common.mak

CFLAGS		+= -Iinclude

iCC             = $(shell find /opt/intel/cc/*/bin/icc)
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

SBINFILES       = artnet2artraw2

OBJS_ARTNET		= artnet2artraw2.o

OSD		= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)
LIBOSD		= $(OSD)/lib$(OSD).a

all: $(SBINFILES)

$(LIBOSD):
	$(MAKE) -C $(OSD)

artnet2artraw2$(EXE): $(OBJS_ARTNET) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_ARTNET) -o $(@) $(LIBS)
