#ifndef LIBRUNT_MAPS_H_
#define LIBRUNT_MAPS_H_

#include <string.h>
#include <unistd.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#else
#include <fcntl.h>
#endif
#include <stdlib.h> /* for abort() */

/* Don't include stdio -- trap-syscalls won't like it, for example. */
int sscanf(const char *str, const char *format, ...);
int open(const char *pathname, int flags, ...);

/* Rethinking this "maps" concept in the name of portability (to FreeBSD), we have
 *
 * a "line" that is really a "raw entry" and read via sysctl() or read();
 * a "proc entry" which is our abstraction of a memory mapping.
 *
 * Then we have some functions:
 * get_a_line really reads a single raw entry into the user's buffer;
 * process_one_maps_line decodes a raw entry and calls the cb on the decoded entry;
 * for_each_maps_entry is a loop that interleaves get_a_line with process_one;
 *
 * In trap-syscalls we avoid race conditions by doing it differently: rather
 * than use for_each_maps_entry, we snapshot all the raw entries and then
 * call process_one on each.
 *
 */

static inline intptr_t get_maps_handle(void)
{
#ifdef __FreeBSD__
	int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid() };
	size_t len;
	len = 0;
	int error = sysctl(name, sizeof name / sizeof name[0], NULL, &len, NULL, 0);
	if (error) return (intptr_t) NULL;
	/* Massive HACK: allow for 33% growth in the memory mapping count. libprocstat does this
	 * in FreeBSD, so it "must be okay". */
	size_t fudged_len = len * 4 / 3;
	char *buf = malloc(sizeof (off_t) + fudged_len);
	if (buf)
	{
		error = sysctl(name, sizeof name / sizeof name[0], buf + sizeof (off_t), &fudged_len, NULL, 0);
		if (error)
		{
			free(buf);
			return (intptr_t) NULL;
		}
	}
	return buf;
	#if 0
		char *pos = buf + sizeof (off_t);
		size_t minimum_packed_struct_size = offsetof(struct kinfo_vmentry, kve_path);
		char **start_positions = malloc(sizeof (char*) * fudged_len / minimum_packed_struct_size);
		if (start_positions)
		{
			size_t *struct_sizes = malloc(sizeof (size_t) * fudged_len / minimum_packed_struct_size);
			if (struct_sizes)
			{
				while (pos < buf + sizeof (off_t) + fudged_len)
				{
					struct kinfo_vmentry *kv = (struct kinfo_vmentry *) pos;
					if (kv->kve_structsize == 0) break;
					pos += kv->kve_structsize;
					start_positions[cnt] = pos;
					struct_sizes[cnt] = kv->kve_structsize;
					cnt++;
				}
				/* We need to give the caller
				 * a single buffer that they can easily iterate through
				 * and then free in one go.
				 * So we reallocate the buffer to the actual size required,
				 * then work backwards to copy the packed structs onto
				 * the old storage. By the end we will be overwriting the
				 * packed records. */
				buf = realloc(buf, cnt * sizeof (struct kinfo_vmentry));
				if (buf)
				{
					for (int i = cnt - 1; i >= 0; --i)
					{
						memcpy(((struct kinfo_vmentry *) buf) + i, start_positions[i], struct_sizes[i]);
					}
				}
				free(struct_sizes);
			}
			free(start_positions);
		}

	kiv = calloc(cnt, sizeof(*kiv));
	if (kiv == NULL) {
		free(buf);
		return (NULL);
	}
	bp = buf;
	eb = buf + len;
	kp = kiv;
	/* Pass 2: unpack */
	while (bp < eb) {
		kv = (struct kinfo_vmentry *)(uintptr_t)bp;
		if (kv->kve_structsize == 0)
			break;
		/* Copy/expand into pre-zeroed buffer */
		memcpy(kp, kv, kv->kve_structsize);
		/* Advance to next packed record */
		bp += kv->kve_structsize;
		/* Set field size to fixed length, advance */
		kp->kve_structsize = sizeof(*kp);
		kp++;
	}
	free(buf);
	}
	#endif
#else
	return (intptr_t) open("/proc/self/maps", O_RDONLY);
#endif
}

static inline void free_maps_handle(intptr_t handle)
{
#ifdef __FreeBSD__
	free((void*) handle);
#else
	close(handle);
#endif
}

#ifdef __FreeBSD__
static inline ssize_t get_a_line_from_kinfo(char *buf, size_t size, intptr_t handle)
{
	/* "Getting a line" just means reading one raw record into a buffer. */
	char *handle_buf_start =  (char*) handle + sizeof (off_t);
	char *handle_pos = handle_buf_start + *(off_t *)handle_buf_start;
	size_t sz = ((struct kinfo_vmentry *)(char*) handle)->kve_structsize;
	ssize_t actual_size_to_copy = (sz < size) ? sz : size;
	*(off_t *)handle_buf_start += actual_size_to_copy;
	memcpy(buf, (char*) handle_pos, actual_size_to_copy);
	return actual_size_to_copy ? actual_size_to_copy : -1;
}
#else
static inline ssize_t get_a_line_from_maps_fd(char *buf, size_t size, intptr_t handle)
{
	if (size == 0) return -1; // now size is at least 1
	int fd = (int) handle;
	// read some stuff, at most `size - 1' bytes (we're going to add a null), into the buffer
	ssize_t bytes_read = read(fd, buf, size - 1);
	// if we read nothing, return -1
	if (bytes_read <= 0) return -1;
	// did we get enough that we have a whole line?
	char *found = memchr(buf, '\n', bytes_read);
	// if so, rewind the file to just after the newline
	if (found)
	{
		ssize_t end_of_newline_displacement = (found - buf) + 1;
		/* HACK: we are effecively doing *signed* arithmetic with an
		 * off_t here, which is of unsigned type. Make sure we use the
		 * full width of the off_t, so that wraparound happens where we
		 * expect it. FIXME: I guess this means lseek() isn't supposed
		 * to support negative offsets from SEEK_CUR? */
		off_t new_off = lseek(fd,
				((off_t) -bytes_read) + (off_t) end_of_newline_displacement /* i.e. negative if we read more */,
				SEEK_CUR);
		// seek should succeed
		if (new_off == (off_t) -1) abort();
		// replace newline with null; caller can strncpy
		buf[end_of_newline_displacement] = '\0';
		// distance to just past the newline is the #bytes read
		return end_of_newline_displacement;
	}
	else
	{
		/* We didn't read enough. But that should only be because of EOF or error.
		 * So just return whatever we got. */
		buf[bytes_read] = '\0';
		return -1;
	}
}
struct maps_buf
{
	char *buf;
	off_t pos;
	size_t len;
};
static inline ssize_t get_a_line_from_maps_buf(char *outbuf, size_t outsize, intptr_t handle)
{
	if (outsize == 0) return -1; // now size is at least 1
	struct maps_buf *m = (struct maps_buf *) handle;
	// read some stuff, at most `size - 1' bytes (we're going to add a null), into the line buffer
	// HACK: we may not have MIN, so...
	#ifndef MIN
	#define MIN(x, y) ((x) > (y) ? (y) : (x))
	#define MIN_defined
	#endif
	size_t max_size_to_copy = MIN(outsize - 1, m->len - m->pos);
	if (max_size_to_copy == 0) return -1; // EOF-like case
	strncpy(outbuf, m->buf + m->pos, max_size_to_copy);
	// ensure that even in the worst case, we're NUL-terminated
	outbuf[MIN(outsize, max_size_to_copy) - 1] = '\0';
	#ifdef MIN_defined
	#undef MIN_defined
	#undef MIN
	#endif
	size_t bytes_read = strlen(outbuf);
	// did we get enough that we have a whole line?
	char *found = memchr(outbuf, '\n', bytes_read);
	// if so, rewind the file to just after the newline
	if (found)
	{
		m->pos += 1 + (found - outbuf);
		return bytes_read + 1;
	}
	else
	{
		/* Else we didn't read enough. But that should only be because of EOF or error.
		 * So just return whatever we got. */
		m->pos += 1 + strlen(outbuf);
		return -1;
	}
}
#endif
struct maps_entry
{
	unsigned long first, second;
	char r, w, x, p;
	unsigned offset;
	unsigned devmaj, devmin;
	unsigned inode;
	char rest[4096];
};
typedef int maps_cb_t(struct maps_entry *ent, char *linebuf, void *arg);

static inline
int read_all_maps_lines_from_fd(int fd, char *linebuf, size_t linebuf_size,
		char **lines, size_t nlines, char *allbuf, size_t allbuf_size)
{
	unsigned n = 0;
	char *allbuf_pos = allbuf;
	ssize_t linesz;
	while (-1 != (linesz = get_a_line_from_maps_fd(linebuf, linebuf_size, fd)))
	{
		/* I have seen alloca blow the stack here on 32-bit, so use a static buffer
		 * that is passed in by the caller (allbuf).
		 * We simply fill the buffer with all the data we get from get_a_line...(),
		 * and point lines[i] into it at the start-of-line positions. */
		//char *a = alloca(linesz + 1);
		char *start_of_line = allbuf_pos;
		// if the combined offset exceeds the size of allbuf, we give up
		if ((allbuf_pos - &allbuf[0]) + linesz + 1 > allbuf_size) return -n;
		allbuf_pos += (linesz + 1);
		lines[n] = start_of_line;
		assert(lines[n]);
		// copy info allbuf from linebuf
		strncpy(lines[n], linebuf, linesz);
		lines[n][linesz] = '\0';
		++n;
		if (n == nlines) { n *= -1; break; }
	}
	return n; // negative n means we failed to read everything, but got that many lines
}

static inline int process_one_maps_line(char *linebuf, struct maps_entry *entry_buf_to_fill,
	maps_cb_t *cb, void *arg)
{
#ifdef __FreeBSD__
	struct kinfo_vmentry *kve = (struct kinfo_vmentry *) linebuf;
	/* Populate the entry buf with data from the kinfo_vmentry. */
	*entry_buf_to_fill = (struct maps_entry) {
		.first = kve->kve_start,
		.second = kve->kve_end,
		.r = kve->kve_protection & KVME_PROT_READ ? 'r' : '-',
		.w = kve->kve_protection & KVME_PROT_WRITE ? 'w' : '-',
		.x = kve->kve_protection & KVME_PROT_EXEC ? 'x' : '-',
		.p = 'p' /* FIXME */,
		.offset = kve->kve_offset,
		.devmaj = 0 /* FIXME */,
		.devmin = 0 /* FIXME */,
		.inode = kve->kve_vn_fileid,
		.rest = kve->kve_path
	};
#else
	#define NUM_FIELDS 11
	entry_buf_to_fill->rest[0] = '\0';
	int fields_read = sscanf(linebuf, 
		"%lx-%lx %c%c%c%c %8x %4x:%4x %d %4095[\x01-\x09\x0b-\xff]\n",
		&entry_buf_to_fill->first, &entry_buf_to_fill->second, &entry_buf_to_fill->r, &entry_buf_to_fill->w, &entry_buf_to_fill->x,
		&entry_buf_to_fill->p, &entry_buf_to_fill->offset, &entry_buf_to_fill->devmaj, &entry_buf_to_fill->devmin,
		&entry_buf_to_fill->inode, entry_buf_to_fill->rest);
	// to help debugging, print the bad line
	if (fields_read < (NUM_FIELDS-1))
	{
		write(2, linebuf, strlen(linebuf)+1);
	}
	assert(fields_read >= (NUM_FIELDS-1)); // we might not get a "rest"
	#undef NUM_FIELDS
#endif
	int ret = cb(entry_buf_to_fill /* now filled! */, linebuf, arg);
	if (ret) return ret;
	else return 0;
}

static inline int for_each_maps_entry(intptr_t handle,
	ssize_t (*get_a_line)(char *, size_t, intptr_t),
	char *linebuf, size_t bufsz, struct maps_entry *entry_buf,
	maps_cb_t *cb, void *arg)
{
	while (get_a_line(linebuf, bufsz, handle) != -1)
	{
		int ret = process_one_maps_line(linebuf, entry_buf, cb, arg);
		if (ret) return ret;
	}
	return 0;
}

#endif
