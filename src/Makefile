THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBRUNT := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))../
srcdir := $(SRCROOT)/src

CFLAGS += -DIN_LIBRUNT_DSO

CFLAGS += -std=gnu11 -fPIC -Wall -Wextra -g
CFLAGS += -I../include -I$(SRCROOT)/include -I$(LIBMALLOCHOOKS) \
   -I$(LIBSYSTRAP) -I$(LIBRUNT)/include -I$(LIBDLBIND)/include -I$(srcdir) -Wno-unused
CFLAGS += -flto -ffat-lto-objects
CFLAGS += -ffunction-sections   # clients may want to wrap individual functions
LDFLAGS += -L$(LIBDLBIND)/lib

# run-from-srcdir case:
# if the current dir is the source dir, change to the output directory
# and re-invoke this makefile from there.
# If we don't know which output directory we want, we want the production one.
ifeq ($(realpath .),$(realpath $(srcdir)))
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS := default
endif
ifneq ($(DEBUG),)
outdir := debug
else
outdir := opt
endif
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	mkdir -p $(SRCROOT)/build/$(outdir)
	$(MAKE) -C $(SRCROOT)/build/$(outdir) -f $(srcdir)/Makefile $(MAKECMDGOALS)
else
# the rest
vpath %.c $(srcdir)

#%.o:: %.c
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

librunt.so: $(srcdir)/librunt.so
	cp $< $@

# if we're building from a dir called "debug"
ifeq ($(notdir $(realpath .)),debug)
DEBUG := 1
endif

.PHONY: default
default: all # autotools likes an 'all' target (I think)

# What binaries do we build?
TARGETS += librunt_preload.so    # the main binary
TARGETS += librunt_preload.a     # in archive form, for extending libraries to link in (liballocs, libcrunch)
TARGETS += librunt.so            # nasty linker script for clients, working around uniqueness problem
TARGETS += librunt_nonshared.a   # uniqtypes and (own-malloc) allocator stubs; linker script points to this, s.t. client exes (-lrunt) get this linked in statically
TARGETS += librunt.a             # the main binary usable for statically-linked client exes -- no uniqueness problem
TARGETS += librunt_dummyweaks.so # non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
TARGETS += librunt_dummyweaks.o  # non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
                                   # (what do client solibs get? easiest is just to treat them like exes, *except* I *think* they don't get nonshared_hooks.o)

.PHONY: all
all: $(TARGETS)

ifeq ($(DEBUG),)
    # FIXME: check this is still true: -O3 -DNDEBUG is the fastest, faster than -O4!
    CFLAGS += -O3 -DNDEBUG
endif

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
LDFLAGS += -Wl,-O2 -flto -Bsymbolic-functions -fPIC 


# different outputs involve different subgroups of objects
UTIL_OBJS :=
ifneq ($(USE_REAL_LIBUNWIND),)
LDLIBS += -lunwind -lunwind-`uname -m`
CFLAGS += -DUSE_REAL_LIBUNWIND
else
CFLAGS += -fno-omit-frame-pointer
endif
MAIN_OBJS := librunt.o auxv.o files.o segments.o sections.o symbols.o tls.o $(UTIL_OBJS)
PRELOAD_OBJS := preload.o

# Generate deps.
ALL_OBJS := $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(NONSHARED_OBJS) $(PRELOAD_OBJS)
# enumerate src files backwards from our .o files
# -- HACK: nonshared_hooks.o is not built from .c source
DEP_OBJS := $(filter-out $(NONSHARED_OBJS),$(ALL_OBJS))
C_SRC := $(sort $(patsubst %.o,%.c,$(DEP_OBJS)))
# Becuase of our vpath'd rules, we can't do patsubst on the source path to get the
# obj path... $< will be something wacky. Instead, work from the object file.
# All our objs are from C files, for now
C_OBJ_DEPS := $(foreach f,$(DEP_OBJS),$(patsubst %.o,%.d,$(f)))
DEPS := $(C_OBJ_DEPS)
$(info C_OBJ_DEPS are $(C_OBJ_DEPS))
# ARGH. If we define a rule verbatim inside $(foreach ), it doesn't actually get
# defined. So we have to use eval.
define rule-for-depfile =
$(patsubst %.o,%.d,$(1)): $(patsubst %.o,%.c,$(1))
	mkdir -p $$(dir $$@) && $$(CC) -MM -MT $(1) $$(CFLAGS) "$$<" > "$$@" || (rm -f "$$@"; false)
endef
$(foreach f,$(DEP_OBJS),$(eval $(call rule-for-depfile,$(f))))
include $(DEPS)

LIBRUNT_PRELOAD_A_OBJS := $(MAIN_OBJS) $(PRELOAD_OBJS)
LIBRUNT_NONSHARED_A_OBJS := $(NOPRELOAD_OBJS) $(NONSHARED_OBJS)
LIBRUNT_A_OBJS := $(MAIN_OBJS) $(NOPRELOAD_OBJS) # $(PRELOAD_OBJS)
OBJCOPY ?= objcopy
librunt_preload.so: LDLIBS += -ldl $(LIBUNWIND_LDLIBS)
# We must use gold to link, because BFD linker complains about
# "relocation R_X86_64_PC32 against protected symbol `...'
#  can not be used when making a shared object"
# ... apparently defeating what I thought was the purpose of 'protected'.
# It makes sense for protected data, but not for protected functions,
# since those can't be copy-reloc'd. The right solution is to forbid
# copy relocs on protected symbols, not to forbid PC-relative reference
# to them. Some versions of BFD still use the more conservative "refuse
# to local-bind to protecteds" (on the grounds that they *might* be
# copy-reloc'd and hence reside elsewhere). See binutils bug 19612.
# Since the linker doesn't know that the reference is to code, not data,
# the BFD argument seems to be that allowing this is a gold bug. If gold
# stops allowing us to link, we probably need to forget "protected" and
# use a pair of aliases, one hidden and one default.
librunt_preload.so: LDFLAGS += -fuse-ld=gold
# Our .o files come with references to internally-named functions like
# __private_malloc and so on. Some extenders (liballocs, libcrunch...)
# will want to provide these, but we just defsym them to the usual.
LIBRUNT_PRELOAD_SO_REDEFINES ?= __private_malloc=malloc \
__private_free=free \
__private_strdup=strdup
# To make the defsym'ing happen, we do objcopy on the .a file.
# FIXME: why not just give --defsym to ld? There's probably a reason....
librunt_preload.so: librunt_preload.a # dlmalloc.a
	tmparch="$$(mktemp)" && \
	 $(OBJCOPY) $(foreach r,$(LIBRUNT_PRELOAD_SO_REDEFINES),--redefine-sym $(r)) $< "$$tmparch" && \
	$(CC) $(filter-out,-flto,$(CFLAGS)) \
	-shared -o "$@" -fno-lto \
	$(filter-out -flto,$(LDFLAGS)) $(LDLIBS) \
        -Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
        -Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr \
	-Wl,--whole-archive "$$tmparch" -Wl,--no-whole-archive; \
	status=$$?; echo NOT REALLY rm -f "$$tmparch"; exit "$$status"

%.a:
	$(AR) r "$@" $+
librunt_preload.a: $(LIBRUNT_PRELOAD_A_OBJS)
librunt_nonshared.a: $(LIBRUNT_NONSHARED_A_OBJS)
librunt.a: $(LIBRUNT_A_OBJS)

ifeq ($(USE_FAKE_LIBUNWIND),)
FAKE_LIBUNWIND_OBJ :=
LIBUNWIND_LDLIBS := -lunwind -lunwind-$(shell uname -m)
else
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
endif

# HACK: would ideally eliminate "dummyweaks" shared object if ld provided a "--dt-useful" option
# or if we could statically link-in our stubs without making them non-overridable.
# Perhaps the custom ld.so will make this feasible.
librunt_dummyweaks.o: dummyweaks.o
	$(LD) -r -o "$@" $+
librunt_dummyweaks.so: dummyweaks.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

# librunt.so is a linker script, so don't remove it
.PHONY: clean
clean: 
	rm -f *.o */*.o $(filter-out librunt.so,$(wildcard *.so)) *.d */*.d *.a

vpath %.h $(srcdir)/%.h

endif # test for run-from-srcdir
