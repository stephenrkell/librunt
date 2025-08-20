# replicate the multiarch build we do in libsystrap/contrib/Makefile

.PHONY: default
# We want "targets" to be the actual files that we want to build.
# But we build them by recursive 'make'. From this makefile, we have
# no way to make these target depend on their source files! So once they
# exist, they will appear not to need rebuilding. Instead we name them
# without the preceding 'build/', and in the rules where we need the
# legit path, we add 'build/' back in. This is similar to making them all
# phony targets (which I tried, using eval, but could not get to work).
TARGETS := $(foreach d,opt-i386 debug-i386 opt-x86_64 debug-x86_64,$(d)/librunt_preload.a)
$(info TARGETS is $(TARGETS))
default: $(TARGETS)

debug-i386/librunt_preload.a opt-i386/librunt_preload.a: MAKE_PREFIX := \
  CC="$(CC) -m32" CPPFLAGS="-D_FILE_OFFSET_BITS=64" ASFLAGS="-m32" LDFLAGS="-Wl,-melf_i386"

debug-%/librunt_preload.a:
	mkdir -p $(dir build/$@) && cd $(dir build/$@) && DEBUG=1 $(MAKE_PREFIX) $(MAKE) -f ../../src/Makefile
opt-%/librunt_preload.a:
	mkdir -p $(dir build/$@) && cd $(dir build/$@) && $(MAKE_PREFIX) $(MAKE) -f ../../src/Makefile

.PHONY: clean
clean:
	rm -rf build
