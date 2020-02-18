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

static const char *asciiz_start;
static const char *asciiz_end;

static const char **env_vector_start;
static const char **env_vector_terminator;

static const char **argv_vector_start;
static const char **argv_vector_terminator;

static ElfW(auxv_t) *auxv_array_start;
static ElfW(auxv_t) *auxv_array_terminator;

static intptr_t *p_argcount;

void *program_entry_point;

static _Bool tried_to_initialize;
void __runt_auxv_init(void) __attribute__((constructor(101)));
void __runt_auxv_init(void)
{
	/* We might get called more than once. */
	if (tried_to_initialize) return;
	tried_to_initialize = 1;

	auxv_array_start = get_auxv((const char **) environ, environ[0]);
	if (!auxv_array_start) return;

	struct auxv_limits lims = get_auxv_limits(auxv_array_start);
	asciiz_start = lims.asciiz_start;
	asciiz_end = lims.asciiz_end;
	env_vector_start = lims.env_vector_start;
	env_vector_terminator = lims.env_vector_terminator;
	argv_vector_start = lims.argv_vector_start;
	argv_vector_terminator = lims.argv_vector_terminator;
	auxv_array_terminator = lims.auxv_array_terminator;
	p_argcount = lims.p_argcount;
	
	ElfW(auxv_t) *found_at_entry = auxv_lookup(auxv_array_start, AT_ENTRY);
	if (found_at_entry) program_entry_point = (void*) found_at_entry->a_un.a_val;
}

void *__top_of_initial_stack __attribute__((visibility("protected")));

_Bool __runt_auxv_get_asciiz(const char **out_start, const char **out_end)
{
	if (out_start) *out_start = asciiz_start;
	if (out_end) *out_end = asciiz_end;
	return 1;
}
_Bool __runt_auxv_get_argv(const char ***out_start, const char ***out_terminator)
{
	if (out_start) *out_start = argv_vector_start;
	if (out_terminator) *out_terminator = argv_vector_terminator;
	return 1;
}

_Bool __runt_auxv_get_env(const char ***out_start, const char ***out_terminator)
{
	if (out_start) *out_start = env_vector_start;
	if (out_terminator) *out_terminator = env_vector_terminator;
	return 1;
}

_Bool __runt_auxv_get_auxv(const Elf64_auxv_t **out_start, Elf64_auxv_t **out_terminator)
{
	if (out_start) *out_start = auxv_array_start;
	if (out_terminator) *out_terminator = auxv_array_terminator;
	return 1;
}
void *__runt_auxv_get_program_entry_point(void)
{
	return program_entry_point;
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
