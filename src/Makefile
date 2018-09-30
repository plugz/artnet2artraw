need := 3.81
ok := $(filter $(need),$(firstword $(sort $(MAKE_VERSION) \
	$(need))))
       
ifndef ok
    $(error fatal error... Need make $(need) but using $(MAKE_VERSION), please upgrade)
endif

AC_ROOT		= .
include		$(AC_ROOT)/common.mak

default: all

all:
	$(MAKE) -C src $(@)
