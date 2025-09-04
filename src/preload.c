/* What we don't (yet) trap: 
 * 
 *  fork(), vfork(), clone()     -- FIXME: do we care about the fork-without-exec case?
 */


#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "librunt_private.h"
/* We don't have raw_write, so... HACK. */
#ifndef RAW_SYSCALL_DEFS_H_
#define raw_write write
#endif
#include "relf.h"
#include "dso-meta.h"

/* NOTE that our wrappers are all init-on-use. This is because
 * we might get called very early, and even if we're not trying to
 * intercept the early calls, we still need to be able to delegate. 
 * For that, we need our underyling function pointers. */

/* Clients may use this to decide whether it's safe to call into
 * the real libdl... we set it when we're about to call into libdl.
 * So if a client gets control, it knows a libdl call is active and
 * it shouldn't do one reentrantly. And we apply the same rule
 * to ourselves. */
_Bool __avoid_libdl_calls;

static char *our_dlerror;
static char *call_orig_dlerror(void);

/* We intercept dlopen() so that we can generate a __runt_files_notify_load() call
 * in those cases where dlopen() actually succeeds and loads a new file (cf.
 * just a RTLD_NOLOAD operation or a call that returns an existing handle). */
void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));
void *dlopen(const char *filename, int flag)
{
	_Bool we_set_flag = 0;
	void *(*dlsym_to_use)(void *, const char *);
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlopen) // happens if we're called before liballocs init
	{
		orig_dlopen = fake_dlsym(RTLD_NEXT, "dlopen");
		if (!orig_dlopen) abort();
	}
	/* We ensure that all files loaded by the first dlopen
	 * have been seen. */
	__runt_files_init();
	if (!early_lib_handles[0]) abort();

	/* The in this block is there to detect whether the file we're loading
	 * is already loaded, and to break early if so. FIXME: why is this necessary?
	 * It seems we should be able to go ahead with the dlopen() call and figure
	 * out from that what happened. In fact we already *do* go ahead, and only
	 * rely on this flag if we get a real link map back. So maybe the right
	 * thing to do here is snapshot the link map and see if we get a new one.
	 * Can a ld.so reallocate link maps? No, I don't think so, at least if it
	 * uses these pointers as the handles returned by dlopen (which we assume
	 * all over the place). FIXME: replace this with a snapshot-then-diff of
	 * the link map. Use qsort and bsearch to avoid being quadratic. */
	void *ret = NULL;
	_Bool file_already_loaded = 0;
	/* FIXME: inherently racy, but does any client really race here? */
	if (filename) 
	{
		const char *file_realname_raw = realpath_quick(filename);
		if (!file_realname_raw) 
		{
			/* The file does not exist. */
			if (strchr(filename, '/') == NULL)
			{
				// FIXME: We are supposed to handle default search paths
				// cf. glibc eld/dl-load.c:_dl_map_object
				// HACK: For now just do a quick search on fixed known system library paths
				// This is non portable!!
				const char *library_sys_paths[] = { "/lib/", "/usr/lib/",
#if defined(__x86_64__)
						"/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/",
#elif defined(__i386__)
						"/lib/i386-linux-gnu/", "/usr/lib/i386-linux-gnu/",
#elif defined(__arm__) && defined(__ARM_EABI__) && defined(__ARM_FP)
						"/lib/arm-linux-gnueabihf/", "/usr/lib/arm-linux-gnueabihf/",
#else
#error "Unrecognised platform"
#endif
						NULL };
				char libfullpath[4096];
				for (const char **libsyspath = library_sys_paths ; !file_realname_raw && *libsyspath ; ++libsyspath)
				{
					strcpy(libfullpath, *libsyspath);
					strcat(libfullpath, filename);
					file_realname_raw = realpath_quick(libfullpath);
				}
				if (!file_realname_raw)
				{
					debug_printf(0, "Failed attempt to load '%s' using system library search paths\n", filename);
					goto skip_load;
				}
			}
			else goto skip_load;
		}
		const char *file_realname = __private_strdup(file_realname_raw);
		for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
		{
			const char *lm_ent_realname = dynobj_name_from_dlpi_name(l->l_name, (void*) l->l_addr);
			file_already_loaded |= (lm_ent_realname && 
					(0 == strcmp(lm_ent_realname, file_realname)));
			if (file_already_loaded) break;
		}
		__private_free((void*) file_realname);
	}
	
	/* FIXME: the logic for avoiding libdl calls is a mess here. Since we
	 * don't have a fake dlopen, we will always call the real one. This
	 * is an issue e.g. when loading meta-objects, which is done via
	 * dl_iterate_phdr and so sets __avoid_libdl_calls. Since the callback
	 * calls dlopen(), it calls us... but then it calls
	 * dlerror, and it will look for the fake dlerror. This clearly isn't
	 * right. As a temporary workaround, propagate dlerror to the fake dlerror
	 * here in this case. I'm not sure what the right fix is. */
	ret = orig_dlopen(filename, flag);
	if (__avoid_libdl_calls && !we_set_flag && !ret)
	{
		our_dlerror = call_orig_dlerror();
	}
skip_load:
	if (we_set_flag) __avoid_libdl_calls = 0;
		
	/* Have we just opened a new object? If filename was null, 
	 * we haven't; if ret is null; we haven't; if NOLOAD was passed,
	 * we haven't. Otherwise we rely on the racy logic above. */
	if (filename != NULL && ret != NULL && !(flag & RTLD_NOLOAD) && !file_already_loaded)
	{
		__runt_files_notify_load(ret, __builtin_return_address(0));
	}

	return ret;
}

int dlclose(void *handle)
{
	/* FIXME: libcrunch needs a way to purge its cache on dynamic unloading,
	 * since it may contain "static" allocations. */

	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	static int (*orig_dlclose)(void *);
	if (!orig_dlclose)
	{
		orig_dlclose = dlsym(RTLD_NEXT, "dlclose");
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlclose);
	}
#if 0
	if (!safe_to_use_bigalloc)
	{
		if (we_set_flag) __avoid_libdl_calls = 0;
		return orig_dlclose(handle);
	}
	else
	{
#endif
		char *copied_filename = strdup(((struct link_map *) handle)->l_name);
		assert(copied_filename != NULL);
		
		int ret = orig_dlclose(handle);
		/* NOTE that a successful dlclose doesn't necessarily unload 
		 * the library! To see whether it's really unloaded, we use 
		 * dlopen *again* with RTLD_NOLOAD. FIXME: probably better
		 * to use raw link map traversal somehow to test this. */
		if (ret == 0)
		{
			// was it really unloaded?
			void *h = orig_dlopen(copied_filename, RTLD_LAZY | RTLD_NOLOAD);
			if (h == NULL)
			{
				// yes, it was unloaded
				__runt_files_notify_unload(copied_filename);
			}
			else 
			{
				// it wasn't unloaded, so we do nothing
			}
		}
	
	// out:
		free(copied_filename);
		if (we_set_flag) __avoid_libdl_calls = 0;
		return ret;
#if 0
	}
#endif
}

static char *(*orig_dlerror)(void);
/* This hack is provided so that we can unconditionally call the original dlerror
 * from dlopen(). */
static char *call_orig_dlerror(void)
{
	if (!orig_dlerror)
	{
		char *saved_msg = our_dlerror;
		// always use the fake dlsym, so we don't clobber the real dlerror
		orig_dlerror = fake_dlsym(RTLD_NEXT, "dlerror");
		if (!orig_dlerror) abort();
		our_dlerror = saved_msg;
	}
	return orig_dlerror();
}
char *dlerror(void)
{
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }

	// we only call the original if our error is NULL *and*
	// we think it's safe to call down
	char *ret;
	if (our_dlerror || __avoid_libdl_calls) ret = our_dlerror;
	else /* no error is set here, and it seems safe to call down */ ret = call_orig_dlerror();

	/* clear whatever error we had stored */
	if (our_dlerror) our_dlerror = NULL;

	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

/* Q. How on earth do we override dlsym?
 * A. We use relf.h's fake_dlsym. */
void *dlsym(void *handle, const char *symbol)
{
	static char *(*orig_dlsym)(void *handle, const char *symbol);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlsym)
	{
		orig_dlsym = fake_dlsym(RTLD_NEXT, "dlsym");
		if (orig_dlsym == (void*) -1)
		{
			our_dlerror = "symbol not found";
			orig_dlsym = NULL;
		}
		/* We're in trouble if fake dlsym can't find the real dlsym...
		 * this is part of our bootstrapping strategy. What's goign on?
		 * Maybe we need a fake dlvsym to find these? */
		if (!orig_dlsym) abort();
	}
	
	void *ret = orig_dlsym(handle, symbol);
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}
void *__runt_dlsym(void *handle, const char *symbol) __attribute__((alias("dlsym")));

void *__runt_fake_dlsym(void *handle, const char *symbol)
{
	void *ret = fake_dlsym(handle, symbol);
	if (ret == (void*) -1)
	{
		our_dlerror = "fake dlsym failed";
		ret = NULL;
	}
	return ret;
}

int dladdr(const void *addr, Dl_info *info)
{
	static int(*orig_dladdr)(const void *, Dl_info *);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dladdr)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dladdr = dlsym(RTLD_NEXT, "dladdr");
		if (!orig_dladdr) abort();
	}
	int ret = orig_dladdr(addr, info);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

void *dlvsym(void *handle, const char *symbol, const char *version)
{
	static void *(*orig_dlvsym)(void *, const char*, const char*);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlvsym)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dlvsym = dlsym(RTLD_NEXT, "dlvsym");
		if (!orig_dlvsym) abort();
	}
	void *ret = orig_dlvsym(handle, symbol, version);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

/* FIXME: do the stuff here that we do for dlopen above. */
void *dlmopen(long nsid, const char *file, int mode)
{
	static void *(*orig_dlmopen)(long, const char*, int);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlmopen)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
		if (!orig_dlmopen) abort();
	}
	void *ret = orig_dlmopen(nsid, file, mode);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

int dladdr1(const void *addr, Dl_info *info, void **extra, int flags)
{
	static int(*orig_dladdr1)(const void*, Dl_info *, void**, int);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dladdr1)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dladdr1 = dlsym(RTLD_NEXT, "dladdr1");
		if (!orig_dladdr1) abort();
	}
	int ret = orig_dladdr1(addr, info, extra, flags);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

struct dl_phdr_info;
/* NOTE: if it gives us trouble with calling malloc or taking locks or
 * whatever, we could now write our own dl_iterate_phdr, since we
 * manage to hang on to enough file metadata that we can always reach
 * the phdrs. For now, we try to use the libc one. */
int dl_iterate_phdr(
                 int (*callback) (struct dl_phdr_info *info,
                                  size_t size, void *data),
                 void *data)
{
	// write_string("Blah8\n");
	static int(*orig_dl_iterate_phdr)(int (*) (struct dl_phdr_info *info,
		size_t size, void *data), void*);
	if (!orig_dl_iterate_phdr)
	{
		// write_string("Blah11\n");
		/* Needs to be fake, because if liballocs gets init'd in the middle of a malloc,
		 * the real dlsym would try to reentrantly malloc. */
		orig_dl_iterate_phdr = fake_dlsym(RTLD_NEXT, "dl_iterate_phdr");
		if (orig_dl_iterate_phdr == (void*) -1)
		{
			our_dlerror = "symbol not found";
			orig_dl_iterate_phdr = NULL;
		}
		assert(orig_dl_iterate_phdr);
	}

	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	// write_string("Blah9\n");
	
	// write_string("Blah13\n");
	struct link_map *l = get_highest_loaded_object_below(__builtin_return_address(0));
	// write_string("Blah13.5\n");
	//fprintf(stderr, "dl_iterate_phdr called from %s+0x%x\n", l->l_name, 
	//	(unsigned) ((char*) __builtin_return_address(0) - (char*) l->l_addr));
	//fflush(stderr);
	int ret = orig_dl_iterate_phdr(callback, data);
	// write_string("Blah14\n");
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}
