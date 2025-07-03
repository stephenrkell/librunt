# replicate the multiarch build we do in libsystrap/contrib/Makefile

.PHONY: default
TARGETS := $(foreach d,build/opt-i386 build/debug-i386 build/opt-x86_64 build/debug-x86_64,$(d)/librunt_preload.a)
$(info TARGETS is $(TARGETS))
default: $(TARGETS)

#include Makefile

build/debug-i386/librunt_preload.a build/opt-i386/librunt_preload.a: MAKE_PREFIX := \
  CC="$(CC) -m32" CPPFLAGS="-D_FILE_OFFSET_BITS=64" ASFLAGS="-m32" LDFLAGS="-Wl,-melf_i386"

build/debug-%/librunt_preload.a:
	mkdir -p $(dir $@) && cd $(dir $@) && DEBUG=1 $(MAKE_PREFIX) $(MAKE) -f ../../src/Makefile
build/opt-%/librunt_preload.a:
	mkdir -p $(dir $@) && cd $(dir $@) && $(MAKE_PREFIX) $(MAKE) -f ../../src/Makefile

.PHONY: clean
clean:
	rm -rf build
