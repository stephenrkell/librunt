#define _GNU_SOURCE

#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <link.h>
#include <errno.h>
#include "relf.h"
#include "librunt.h"
#include "librunt_private.h"

#ifdef _LIBGEN_H
#error "exe-name.c needs GNU basename() so must not include libgen.h"
#endif

char *get_exe_command_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_command_fullname(void)
{
	static char exe_fullname[4096];
	static _Bool tried;
	if (!exe_fullname[0] && !tried)
	{
		// grab the executable's filename; if we fail, we won't try again
		tried = 1;
		/* Use auxv, not /proc. It's more portable, sort of. */
		struct auxv_limits limits;
		ElfW(auxv_t) *p_auxv = environ ? get_auxv(environ, &limits) : NULL;
		if (p_auxv)
		{
			limits = get_auxv_limits(p_auxv);
			ElfW(auxv_t) *found_base_ent = auxv_lookup(p_auxv, AT_BASE);
			ElfW(auxv_t) *found_execfn_ent = auxv_lookup(p_auxv, AT_EXECFN);
			if (found_base_ent && found_base_ent->a_un.a_val == 0)
			{
				/* This means the interpreter is masquerading as the
				 * executable. The 'real' executable, which is what we
				 * want, is in the argv. Luckily, the ld.so has fixed
				 * up the argument vector for us. We need to realpath
				 * it, though. */
				strncpy(exe_fullname, realpath_quick(limits.argv_vector_start[0]),
					sizeof exe_fullname);
				exe_fullname[sizeof exe_fullname - 1] = '\0';
				goto out;
			}
			if (found_execfn_ent)
			{
				strncpy(exe_fullname, realpath_quick((char*) found_execfn_ent->a_un.a_val),
					sizeof exe_fullname);
				exe_fullname[sizeof exe_fullname - 1] = '\0';
				goto out;
			}
		}
		// OK, fall back on /proc
		// FIXME: this is sysdep!
		int ret __attribute__((unused))
		 = readlink("/proc/self/exe", exe_fullname, sizeof exe_fullname);
		errno = 0;
	}
out:
	if (exe_fullname[0]) return exe_fullname;
	else return NULL;
}

char *get_exe_dynobj_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_dynobj_fullname(void)
{
	static char exe_fullname[4096];
	static _Bool tried;
	if (!exe_fullname[0] && !tried)
	{
		int ret __attribute__((unused))
		 = readlink("/proc/self/exe", exe_fullname, sizeof exe_fullname);
		errno = 0;
	}
	if (exe_fullname[0]) return exe_fullname;
	else return NULL;
}

/* better name for the public version */
const char *__runt_get_exe_realpath(void)
{ return get_exe_dynobj_fullname(); }

char *get_exe_command_basename(void) __attribute__((visibility("hidden")));
char *get_exe_command_basename(void)
{
	static char exe_basename[4096];
	static _Bool tried;
	if (!exe_basename[0] && !tried)
	{
		tried = 1;
		char *exe_fullname = get_exe_command_fullname();
		if (exe_fullname)
		{
			strncpy(exe_basename, basename(exe_fullname), sizeof exe_basename); // GNU basename
			exe_basename[sizeof exe_basename - 1] = '\0';
		}
	}
	if (exe_basename[0]) return exe_basename;
	else return NULL;
}

// FIXME: modularise sysdep stuff better
#if defined(__x86_64__)
const char __ldso_name[] __attribute__((visibility("protected"))) = "/lib64/ld-linux-x86-64.so.2";
#elif defined (__i386__)
const char __ldso_name[] __attribute__((visibility("protected"))) = "/lib/ld-linux.so.2";
#elif defined (__arm__) && defined(__ARM_EABI__) && defined(__ARM_FP)
const char __ldso_name[] __attribute__((visibility("protected"))) = "/lib/ld-linux-armhf.so.3";
#else
#error "Unrecognised architecture/ABI"
#endif
