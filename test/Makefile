THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
# -include $(dir $(THIS_MAKEFILE))/../config.mk

UNIQTYPES_BASE ?= /usr/lib/meta
META_BASE ?= /usr/lib/meta
# We want to test the most recent build, whether 'opt' or 'debug'.
# We used to look at timestamps in build/, but just use 'lib'.
LIBRUNT_LIB_DIR ?= $(realpath $(dir $(THIS_MAKEFILE))/..)/lib
LIBRUNT_BUILD ?= $(realpath $(LIBRUNT_LIB_DIR)/outdir)/librunt_preload.so

export LIBRUNT_LIB_DIR
export LIBRUNT_BUILD

CFLAGS += -g -I$(realpath $(dir $(THIS_MAKEFILE)))/../include
LDFLAGS += -L$(LIBRUNT_LIB_DIR)
# HMM -- this is causing us to re-add the +='d stuff in each recursive make.
# can we get away without this?
export CFLAGS
export LDFLAGS

cases := $(filter-out unit-tests,$(sort $(wildcard [-a-z]*)))

LIBRUNT := $(realpath $(dir $(THIS_MAKEFILE))/..)
export LIBRUNT

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(LIBRUNT_BUILD)),)
        $(error You must first build librunt_preload.so and (if necessary) link it at $(LIBRUNT_BUILD))
endif
endif

export PRELOAD := "$(LIBRUNT_BUILD)"

default: checkall
checkall: $(patsubst %,checkrun-%,$(cases))

# Some cases are expected to fail
checkrun-fail-%:
	@echo "expected-fail case is fail-$*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	$(MAKE) cleanrun-fail-$* 1>$$out 2>$$err && \
		tail -n6 "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0\+.* [1-9][0-9]*.* 0\+$$' >/dev/null || \
		(tail -n20 $$err; false)
# special: this failing case aborts, for now
checkrun-fail-alloca-clang:
	@echo "expected-fail case is fail-alloca-clang" && \
		out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
		err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
		! $(MAKE) cleanrun-fail-alloca-clang 1>$$out 2>$$err

# Some cases are expected to abort
checkrun-abort-%:
	@echo "expected-fail case is abort-$*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	if $(MAKE) cleanrun-abort-$* 1>$$out 2>$$err; then false; else true; fi
# Some cases are special and require only an exit status of zero
checkrun-hello:
	$(MAKE) cleanrun-hello >/dev/null 2>&1
checkrun-query:
	$(MAKE) cleanrun-query >/dev/null 2>&1
checkrun-dlfcn:
	$(MAKE) cleanrun-dlfcn >/dev/null 2>&1
checkrun-find-r-debug:
	$(MAKE) cleanrun-find-r-debug >/dev/null 2>&1
checkrun-relf-auxv-dynamic:
	$(MAKE) cleanrun-relf-auxv-dynamic >/dev/null 2>&1
checkrun-relf-auxv-static:
	$(MAKE) cleanrun-relf-auxv-static >/dev/null 2>&1

# Most test cases should output a librunt summary in which 
# -- FIXME
checkrun-%:
	@echo "case is $*" && \
	out=$$( echo -n "out is " 1>&2; mktemp | tee /dev/stderr ) && \
	err=$$( echo -n "err is " 1>&2; mktemp | tee /dev/stderr ) && \
	$(MAKE) cleanrun-$* 1>$$out 2>$$err && \
		tail -n6 "$$err" | tr '\n' '\f' | \
		grep ' 0.* 0.* 0.* 0=\+$$' >/dev/null || \
		(tail -n20 $$err; false)

# disabled cases
# (none right now)

# run logic

INCLUDE_MK_INC = `if test -e $(dir $(realpath $(THIS_MAKEFILE)))/$*/mk.inc; then /bin/echo -f mk.inc; else true; fi`

_onlyrun-nopreload-%:
	./nopreload-$*

_onlygdbrun-nopreload-%:
	gdb --args ./nopreload-$* ./nopreload-$*

_onlyrun-%:
	LD_PRELOAD=$(PRELOAD) ./$*

_onlygdbrun-%:
	gdb --eval-command "set environment LD_PRELOAD=$(PRELOAD)" --args ./$* ./$*

build-%:
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) "$*" 

run-%:
	$(MAKE) build-$* && ( $(MAKE) -C "$*" $(INCLUDE_MK_INC) -f ../Makefile _onlyrun-$* )

cleanbuild-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && \
	$(MAKE) build-$* 

cleanrun-%: 
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && \
	$(MAKE) run-$*

gdbrun-%: # run the test case with itself as input
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) "$*" && ( cd "$*" && $(MAKE) $(INCLUDE_MK_INC) -f ../Makefile _onlygdbrun-$* )

gdbcleanrun-%:
	$(MAKE) -C $* $(INCLUDE_MK_INC) -f ../Makefile clean && $(MAKE) gdbrun-$*

clean-%:
	$(MAKE) -C "$*" $(INCLUDE_MK_INC) -f $(realpath $(THIS_MAKEFILE)) clean

default:
	for case in $(cases); do \
            $(MAKE) run-$$case; \
        done

# generic clean rule that we can run from test dirs too (with $(MAKE) -f ../Makefile)
clean: # (delete anything whose name is a prefix of a .c file's and doesn't contain a dot)
	rm -f $(filter-out .,$(patsubst %.c,%,$(shell find -name '*.c')))
	find -name '*.cil.*' -o -name '*.i' -o -name '*.o' -o \
	     -name '*.s' -o -name '*.allocs' -o -name '*.so' -o -name '*.ltrans.out' -o \
	     -name '*.allocstubs.c' -o -name '*.fixuplog' | xargs rm -f

.PHONY: unit-tests
unit-tests:
	$(MAKE) -C unit-tests
