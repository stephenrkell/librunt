#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include "relf.h"
#include "librunt_private.h"

const char *__auxv_asciiz_start __attribute__((visibility("protected")));
const char *__auxv_asciiz_end __attribute__((visibility("protected")));

const char **__env_vector_start __attribute__((visibility("protected")));
const char **__env_vector_terminator __attribute__((visibility("protected")));

const char **__argv_vector_start __attribute__((visibility("protected")));
const char **__argv_vector_terminator __attribute__((visibility("protected")));

ElfW(auxv_t) *__auxv_array_start __attribute__((visibility("protected")));
ElfW(auxv_t) *__auxv_array_terminator __attribute__((visibility("protected")));

intptr_t *__auxv_program_argcountp __attribute__((visibility("protected")));

void *__program_entry_point __attribute__((visibility("protected")));
void *__top_of_initial_stack __attribute__((visibility("protected")));

static _Bool tried_to_initialize;
void __runt_auxv_init(void) __attribute__((constructor(101)));
void __runt_auxv_init(void)
{
	/* We might get called more than once. */
	if (tried_to_initialize) return;
	tried_to_initialize = 1;

	/* PROBLEM. we might want to be called before libc is initialized.
	 * E.g. we do this in trace-syscalls.so, which uses *us* to get
	 * the auxv address and initialize its private copy of musl. BUT
	 * we bootstrap access to the auxv via environ, which is not yet
	 * initialized if libc is not initialized.
	 * HACK: we use __libc_stack_end if it is defined. */
	if (!environ && !&__libc_stack_end) abort();
	if (environ) __auxv_array_start = get_auxv((char **) environ, environ[0]);
	else __auxv_array_start = get_auxv_via_libc_stack_end();
	if (!__auxv_array_start) return;

	struct auxv_limits lims = get_auxv_limits(__auxv_array_start);
	__auxv_asciiz_start = lims.asciiz_start;
	__auxv_asciiz_end = lims.asciiz_end;
	__env_vector_start = lims.env_vector_start;
	__env_vector_terminator = lims.env_vector_terminator;
	__argv_vector_start = lims.argv_vector_start;
	__argv_vector_terminator = lims.argv_vector_terminator;
	__auxv_array_terminator = lims.auxv_array_terminator;
	__auxv_program_argcountp = lims.p_argcount;
	
	ElfW(auxv_t) *found_at_entry = auxv_lookup(__auxv_array_start, AT_ENTRY);
	if (found_at_entry) __program_entry_point = (void*) found_at_entry->a_un.a_val;
}


_Bool __runt_auxv_get_asciiz(const char **out_start, const char **out_end)
{
	if (out_start) *out_start = __auxv_asciiz_start;
	if (out_end) *out_end = __auxv_asciiz_end;
	return 1;
}
_Bool __runt_auxv_get_argv(const char ***out_start, const char ***out_terminator)
{
	if (out_start) *out_start = __argv_vector_start;
	if (out_terminator) *out_terminator = __argv_vector_terminator;
	return 1;
}

_Bool __runt_auxv_get_env(const char ***out_start, const char ***out_terminator)
{
	if (out_start) *out_start = __env_vector_start;
	if (out_terminator) *out_terminator = __env_vector_terminator;
	return 1;
}

_Bool __runt_auxv_get_auxv(const ElfW(auxv_t) **out_start, ElfW(auxv_t) **out_terminator)
{
	if (out_start) *out_start = __auxv_array_start;
	if (out_terminator) *out_terminator = __auxv_array_terminator;
	return 1;
}
void *__runt_auxv_get_program_entry_point(void)
{
	return __program_entry_point;
}

/* Typically on a Linux machine, the key/value content of the auxv would include
 * the following information.
 
AT_SYSINFO_EHDR // vdso's base address
AT_HWCAP        // bitmask of processor capabilities
AT_PAGESZ       // page size
AT_CLKTCK       // granularity of times(2)
AT_PHDR         // program headers address
AT_PHENT        // size of one phdr
AT_PHNUM        // number of phdrs
AT_BASE         // base address of the interpreter (usu. dynamic linker)
AT_FLAGS        // flags (unused on Linux)
AT_ENTRY        // entry point of executable
AT_UID          // real user ID
AT_EUID         // effective user ID
AT_GID          // real group ID
AT_EGID         // effective group ID
AT_SECURE       // nonzero if caps/uids elevated => libc/ld.so have modified behaviour
AT_RANDOM       // pointer to 16 bytes of random data
AT_EXECFN       // pointer to string containing pathname by which program was executed
AT_PLATFORM     // pointer to string identifying platform, as used by ld.so to interpret rpath

*/
