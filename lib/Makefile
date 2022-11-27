THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SRCROOT := $(realpath $(dir $(THIS_MAKEFILE))/..)

default: all

SYMLINKS := librunt_preload.a librunt_preload.so \
    librunt_dummyweaks.o librunt_dummyweaks.so librunt.a \
    librunt.so

# Now that we build in '$(SRCROOT)/build/<outdir>', where <outdir> might
# be 'opt' or 'debug', we have a problem -- which one do we symlink?
# The answer is that we symlink the outdir, then make our symlinks point
# under there.
ifneq ($(DEBUG),)
outdir := debug
else
outdir := opt
endif

all: outdir $(SYMLINKS)

ifneq ($(notdir $(shell readlink outdir)),$(outdir))
.PHONY: outdir
endif
outdir:
	rm -f outdir
	ln -sf ../build/$(outdir) $@

$(filter-out librunt.so,$(SYMLINKS)): %: $(SRCROOT)/build/$(outdir)/%
	ln -sf outdir/$(notdir $<) "$@"

# the librunt.so file is now just the preload .so file
librunt.so: librunt_preload.so
	ln -sf $< $@

clean:
	rm -f outdir $(SYMLINKS) librunt.so
