#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <link.h>
#include <errno.h>
#include "relf.h"
#include "librunt.h"
#include "librunt_private.h"

#ifdef _LIBGEN_H
#error "librunt.c needs GNU basename() so must not include libgen.h"
#endif

char *get_exe_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_fullname(void)
{
	static char exe_fullname[4096];
	static _Bool tried;
	if (!exe_fullname[0] && !tried)
	{
		tried = 1;
		// FIXME: this is sysdep!
		// grab the executable's basename; if we fail, we won't try again
		int ret __attribute__((unused))
		 = readlink("/proc/self/exe", exe_fullname, sizeof exe_fullname);
		errno = 0;
	}
	if (exe_fullname[0]) return exe_fullname;
	else return NULL;
}

char *get_exe_basename(void) __attribute__((visibility("hidden")));
char *get_exe_basename(void)
{
	static char exe_basename[4096];
	static _Bool tried;
	if (!exe_basename[0] && !tried)
	{
		tried = 1;
		char *exe_fullname = get_exe_fullname();
		if (exe_fullname)
		{
			strncpy(exe_basename, basename(exe_fullname), sizeof exe_basename); // GNU basename
			exe_basename[sizeof exe_basename - 1] = '\0';
		}
	}
	if (exe_basename[0]) return exe_basename;
	else return NULL;
}

const char __ldso_name[] = "/lib64/ld-linux-x86-64.so.2"; // FIXME: sysdep
FILE *stream_err __attribute__((visibility("hidden")));

int __librunt_debug_level;
_Bool __librunt_is_initialized;

// these two are defined in addrmap.h as weak
unsigned long __addrmap_max_stack_size;

// HACK
void __librunt_preload_init(void);

struct dl_for_one_phdr_cb_args
{
	struct link_map *link_map_to_match;
	int (*actual_callback) (struct dl_phdr_info *info, size_t size, void *data);
	void *actual_arg;
};

static int dl_for_one_phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct dl_for_one_phdr_cb_args *args = (struct dl_for_one_phdr_cb_args *) data;
	/* Only call the callback if the link map matches. */
	if (args->link_map_to_match->l_addr == info->dlpi_addr)
	{
		return args->actual_callback(info, size, args->actual_arg);
	} else return 0; // keep going
}

int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data)
{
	struct dl_for_one_phdr_cb_args args = {
		(struct link_map *) handle, 
		callback,
		data
	};
	return dl_iterate_phdr(dl_for_one_phdr_cb, &args);
}

#ifndef MAX_EARLY_LIBS
#define MAX_EARLY_LIBS 16
#endif
struct link_map *early_lib_handles[MAX_EARLY_LIBS] __attribute__((visibility("hidden")));
void init_early_libs(void) __attribute__((visibility("hidden")));
void init_early_libs(void)
{
	if (early_lib_handles[0]) return;
	/* We have to scan for the libraries that were active
	 * before we caught our first dlopen.
	 *
	 * Then, when we initialize the static file metadata, we
	 * can avoid double-processing any libs that were opened
	 * by  don't
	 * want todouble-process any files that were already notified
	 * (below) because they were opened with our dlopen wrapper. */
	unsigned idx = 0;
	for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
	{
		if (idx == MAX_EARLY_LIBS) abort();
		early_lib_handles[idx++] = l;
	}
	/* This is snapshotting exactly those libs that are active
	 * when we first trap dlopen. Is that set identical to the
	 * ones we need to snapshot for "early /proc/pid/maps" purposes?
	 * When do we "start trapping dlopens", really? The problem is
	 * that not all DSO loads happen through the public "dlopen" symbol.
	 * But probably it's only the "initial libraries" that fall into
	 * that category. So an "initial objects snapshot" would be fine?
	 * We could just assert that this has already happened in dlopen,
	 * below -- it doesn't have to be triggered from dlopen itself,
	 * and probably shouldn't be.
	 */
}

static _Bool done_init;
void __librunt_main_init(void) __attribute__((constructor(101),visibility("protected")));
// NOTE: runs *before* the constructor in preload.c
void __librunt_main_init(void)
{
	assert(!done_init);
	const char *debug_level_str = getenv("LIBRUNT_DEBUG_LEVEL");
	if (debug_level_str) __librunt_debug_level = atoi(debug_level_str);
	done_init = 1;
}

// FIXME: do better!
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg)
{
	static char buf[4096];
	errno = 0;
	char *ret = realpath(arg, &buf[0]);
	if (errno) { errno = 0; return NULL; }
	return ret;
}

const char *dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr) __attribute__((visibility("protected")));
const char *dynobj_name_from_dlpi_name(const char *dlpi_name, void *dlpi_addr)
{
	if (strlen(dlpi_name) == 0)
	{
		/* libdl can give us an empty name for 
		 *
		 * - the executable;
		 * - itself;
		 * - any others? vdso?
		 */
		if (dlpi_addr == 0) return get_exe_fullname();
		else
		{
			/* HMM -- empty dlpi_name but non-zero load addr.
			 * Is it the vdso? */
			struct link_map *l = get_highest_loaded_object_below((char*) dlpi_addr);
			ElfW(Dyn) *strtab_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
			if (strtab_ent && (intptr_t) strtab_ent->d_un.d_val < 0)
			{
				/* BUGGY vdso, but good enough for me. */
				return "[vdso]";
				//const char *strtab = (const char *) strtab_ent->d_un.d_ptr;
				//ElfW(Dyn) *soname_ent = dynamic_lookup(l->l_ld, DT_SONAME);
				//const char *soname_str = strtab + soname_ent->d_un.d_val;
				//if (strstr(soname_str, "vdso"))
				//{
				//	// okay, vdso
				//	return "[vdso]";
				//}
			}
			else
			{
				/* This is probably a PIE executable or a shared object
				 * being interpreted as an executable. */
				return get_exe_fullname();
			}
		}
	}
	else
	{
		// we need to realpath() it
		const char *maybe_real = realpath_quick(dlpi_name);
		if (maybe_real) return maybe_real;
		/* If realpath said nothing, it's a bogus non-empty filename. 
		 * Return the filename directly. */
		return dlpi_name;
	}
}

void *__librunt_main_bp; // beginning of main's stack frame

int __librunt_global_init(void) __attribute__((constructor(103),visibility("protected")));
int __librunt_global_init(void)
{
	// write_string("Hello from librunt global init!\n");
	if (__librunt_is_initialized) return 0; // we are okay

	// don't try more than once to initialize
	static _Bool tried_to_initialize;
	if (tried_to_initialize) return -1;
	tried_to_initialize = 1;
	
	static _Bool trying_to_initialize;
	if (trying_to_initialize) return 0;
	trying_to_initialize = 1;

	// figure out where our output goes
	const char *errvar = getenv("LIBRUNT_ERR");
	if (errvar)
	{
		// try opening it
		stream_err = fopen(errvar, "w");
		if (!stream_err)
		{
			stream_err = stderr;
			debug_printf(0, "could not open %s for writing\n", errvar);
		}
	} else stream_err = stderr;
	assert(stream_err);

	if (!orig_dlopen) // might have been done by a pre-init call to our preload dlopen
	{
		orig_dlopen = fake_dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlopen);
	}

	__runt_files_init();

	trying_to_initialize = 0;
	__librunt_is_initialized = 1;

	debug_printf(1, "librunt successfully initialized\n");
	
	return 0;
}
