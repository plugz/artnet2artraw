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

LIBSSL		= -lssl -lcrypto
ifeq ($(subst TRUE,true,$(filter TRUE true,$(gcrypt) $(GCRYPT))),true)
	LIBSSL		= -lgcrypt $(LDFLAGS)
	CFLAGS 		+= -DUSE_GCRYPT
	OBJS_ARTNET	+= sha1-git.o
else
	LIBSSL		= -lssl -lcrypto $(LDFLAGS)
endif


ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	LIBSQL		= -L/usr/local/lib -lsqlite3
else
	LIBSQL		=
endif

all: $(SBINFILES)

$(LIBOSD):
	$(MAKE) -C $(OSD)

artnet2artraw2$(EXE): $(OBJS_ARTNET) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_ARTNET) -o $(@) $(LIBS) $(LIBSSL)
