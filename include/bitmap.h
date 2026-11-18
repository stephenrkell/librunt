#ifndef LIBALLOCS_BITMAP_H_
#define LIBALLOCS_BITMAP_H_

#include <assert.h>
#ifdef __cplusplus
#define _Static_assert(args...) static_assert(args)
#endif
// want a truly word-sized integer... let's use uintptr_t for now
#include <stdint.h>
#include "bitops.h"
#include "vas.h"
#include "elfw.h"

#ifndef WORD_BITSIZE
#define WORD_BITSIZE ((sizeof (void*))<<3)
#endif

typedef uintptr_t bitmap_word_t;
#define BITMAP_WORD_NBITS (8*sizeof(bitmap_word_t))

_Static_assert(BITMAP_WORD_NBITS == WORD_BITSIZE, "bitmap word size is platform word size");
_Static_assert(BITMAP_WORD_NBITS == ELF_WORD_BITSIZE, "bitmap word size is ELF word size");

#define popcount_y_(n) popcount ## n
#define popcount_x_(n) popcount_y_(n)
#define popcount_word popcount_x_(ELF_WORD_BITSIZE)

/* We define both "big-endian" and "little-endian" *bit* orders.
 * These are intended for bitmaps whose elements denote bytes.
 * Big-endian mean the lowest-address bit is the most significant.
 * Little-endian means the lowest-address bit is the least significant.
 * Big-endian is best for reverse searches ("find the next lower address...")
 * whereas little-endian is best for forward searches ("find the next higher").
 * To see why, the following shows why big-endian is better for rfind.
	if (*p_bitmap < (1ul<<start_idx))
	{
		// The word has a value less than the query bit pattern, so
		// it can't have the query bit or any higher bit set.
	}
	else
	{
		// The word has a value greater than or equal to the query bit pattern, so
		// it may or may not have the query bit set.
	}
 */

/**********************************************
 * big-endian functions
 **********************************************/

static inline _Bool bitmap_get_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	return p_bitmap[index / BITMAP_WORD_NBITS] & (1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
static inline void bitmap_set_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] |= (1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
static inline void bitmap_clear_b(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] &= ~(1ul << (BITMAP_WORD_NBITS-1-(index % BITMAP_WORD_NBITS)));
}
/* Here we do a reverse search
 * for the first bit set
 * at or below
 * bit position start_idx.
 * We return the index of that bit, or (bitmap_word_t) -1 if no set bit was found.
 */
static inline unsigned long bitmap_rfind_first_set_leq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, long start_pos)
{
	bitmap_word_t *p_base = p_bitmap;
	p_bitmap += start_pos / BITMAP_WORD_NBITS;
	start_pos %= BITMAP_WORD_NBITS;
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		if (*p_bitmap < (1ul<<(BITMAP_WORD_NBITS-1-start_pos)))
		{
			// The word has a value less than the query bit pattern, so
			// it can't have the query bit or any higher-significance (lower-address) bit set.
			// So search lower
			if (p_bitmap == p_base) return (bitmap_word_t) -1;
			--p_bitmap;
			start_pos = BITMAP_WORD_NBITS - 1;
			continue;
		}
		else // *p_bitmap >= (1ul<<(BITMAP_WORD_NBITS-1-start_pos))
		{
			// This is our termination case.
			// The word has a value greater than or equal to the query bit pattern, so
			// it has one or more of the query or any higher-significance (lower-address) bit set.
			// First mask out so we have only the query bit or higher-significance bits set.
			// Then find the highest-address (lowest-significance) bit set.
			// The search result is the (bitmap-wide) position of that bit.
			unsigned query_bit_idx = BITMAP_WORD_NBITS-1-start_pos; // in the range 0..63
			// how many bits are equal-or-higher-significance than the query bit?
			// it's from the query bit idx up to 63
			bitmap_word_t w = *p_bitmap & TOP_N_BITS_SET(BITMAP_WORD_NBITS - query_bit_idx);
			unsigned lowest_significance_bit_idx = ntz(w);
			unsigned that_bit_relative_pos = BITMAP_WORD_NBITS-1-lowest_significance_bit_idx;
			unsigned that_bit_pos = (p_bitmap - p_base) * (BITMAP_WORD_NBITS) + that_bit_relative_pos;
			return that_bit_pos;
		}
	}
	return (bitmap_word_t) -1;
}
static inline unsigned long bitmap_find_first_set1_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long start_idx, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_find_first_set_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_find_first_clear_geq_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	return (bitmap_word_t) -1; // FIXME
}
static inline unsigned long bitmap_count_set_b(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit,
	unsigned long start_idx_ge, unsigned long end_idx_lt)
{
	return (bitmap_word_t) -1; // FIXME
}

/* FIXME: iterating over all doesn't make sense if our bitmap is sparse in memory.
 * Do we have any sparse bitmaps? Probably not yet, but same deal as memtables:
 * we want a coarser-grained bitmap to tell us which (s)parts are in use. */
#define BITMAP_FOR_EACH_SET_B(b, nwords, idxvar, thing) \
    for (bitmap_word_t *p; p != (b) + nwords; ++p) { \
        bitmap_word _t word = *p; \
        u/* big-endian means we start with the MSB */ \
        for (unsigned i = 0; i < BITMAP_WORD_NBITS; word <<= 1, ++i) { \
            if (word & (0x1u << (BITMAP_WORD_NBITS-1))) { \
            } \
        } \
    }

/**********************************************
 * little-endian functions
 **********************************************/

static inline _Bool bitmap_get_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	return p_bitmap[index / BITMAP_WORD_NBITS] & (1ul << (index % BITMAP_WORD_NBITS));
}
static inline void bitmap_set_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] |= (1ul << (index % BITMAP_WORD_NBITS));
}
static inline void bitmap_clear_l(bitmap_word_t *p_bitmap, unsigned long index)
{
	p_bitmap[index / BITMAP_WORD_NBITS] &= ~(1ul << (index % BITMAP_WORD_NBITS));
}
/* Here we do a reverse search
 * for the first bit set
 * at or below
 * bit position start_idx.
 * We return the position (index) of that bit, or (bitmap_word_t) -1 if no set bit was found.
 * Optionally, via out_test_bit we return the bitmask identifying the found bit.
 */
static inline unsigned long bitmap_rfind_first_set_leq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, long start_idx, unsigned long *out_test_bit)
{
	bitmap_word_t *p_base = p_bitmap;
	p_bitmap += start_idx / BITMAP_WORD_NBITS;
	start_idx %= BITMAP_WORD_NBITS;
	if (p_bitmap > p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx >= 0)
		{
			bitmap_word_t test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * BITMAP_WORD_NBITS;
			}
			--start_idx;
		}
		// now start_idx < 0
		if (p_bitmap == p_base) break;
		start_idx = BITMAP_WORD_NBITS - 1;
		--p_bitmap;
	}
	return (unsigned long) -1;
}
/* Here we do a forward search for the first bit set
 * starting at position start_idx.
 * We return its position, or (bitmap_word_t)-1 if not found.
 * Optionally, on success we also output the bitmask identifying that bit.
 */
static inline unsigned long bitmap_find_first_set1_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long start_idx, unsigned long *out_test_bit)
{
	bitmap_word_t *p_base = p_bitmap;
	p_bitmap += start_idx / BITMAP_WORD_NBITS;
	start_idx %= BITMAP_WORD_NBITS;
	if (p_bitmap >= p_limit) return (unsigned long) -1;
	while (1)
	{
		while (start_idx < BITMAP_WORD_NBITS)
		{
			unsigned long test_bit = 1ul << start_idx;
			if (*p_bitmap & test_bit)
			{
				if (out_test_bit) *out_test_bit = test_bit;
				return start_idx + (p_bitmap - p_base) * BITMAP_WORD_NBITS;
			}
			++start_idx;
		}
		// now start_idx < 0
		++p_bitmap;
		if (p_bitmap == p_limit) break;
		start_idx = 0;
	}
	return (unsigned long) -1;
}
static inline unsigned long bitmap_find_first_set_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	bitmap_word_t *p_initial_bitmap;
			
	while (*p_bitmap == (bitmap_word_t) 0
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	// while the test bit is unset...
	while (!(*p_bitmap & test_bit))
	{
		if (__builtin_expect(test_bit != 1ul<<(BITMAP_WORD_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * BITMAP_WORD_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;	
}
static inline unsigned long bitmap_find_first_clear_geq_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit, unsigned long *out_test_bit)
{
	bitmap_word_t *p_initial_bitmap;
			
	while (*p_bitmap == (bitmap_word_t) -1
				&& p_bitmap < p_limit) ++p_bitmap;
	if (p_bitmap == p_limit) return (unsigned long) -1;
	
	/* Find the lowest free bit in this bitmap. */
	unsigned long test_bit = 1;
	unsigned test_bit_index = 0;
	while (*p_bitmap & test_bit)
	{
		if (__builtin_expect(test_bit != 1ul<<(BITMAP_WORD_NBITS - 1), 1))
		{
			test_bit <<= 1;
			++test_bit_index;
		}
		else assert(0); // all 1s --> we shouldn't have got here
	}
	/* FIXME: thread-safety */
	unsigned free_index = (p_bitmap - p_initial_bitmap) * BITMAP_WORD_NBITS
			+ test_bit_index;
	
	if (out_test_bit) *out_test_bit = test_bit;
	return free_index;
}
static inline unsigned long bitmap_count_set_l(bitmap_word_t *p_bitmap, bitmap_word_t *p_limit,
	unsigned long start_idx_ge, unsigned long end_idx_lt)
{
	if (end_idx_lt <= start_idx_ge) return 0;
	bitmap_word_t *p_startword = p_bitmap + (start_idx_ge / BITMAP_WORD_NBITS);
	bitmap_word_t *p_endword = p_bitmap + ((end_idx_lt + (BITMAP_WORD_NBITS-1) / BITMAP_WORD_NBITS));
	start_idx_ge %= BITMAP_WORD_NBITS;
	end_idx_lt %= BITMAP_WORD_NBITS;
	if (p_startword >= p_limit) return (unsigned long) -1;
	if (p_endword >= p_limit) return (unsigned long) -1;
	unsigned long count = 0;
	while (p_startword != p_endword)
	{
		bitmap_word_t word;
		if (start_idx_ge)
		{
			// only count the higher-addressed (most-significant) 
			// BITMAP_WORD_NBITS - start_idx_ge
			// bits.
			word = (*p_startword) >> (BITMAP_WORD_NBITS - start_idx_ge);
		} else word = *p_startword;
		count += popcount_word(word);
		++p_startword;
		start_idx_ge = 0; // start from the beginning of the next word
	}
	// now just handle the last word. BEWARE: start_idx_ge may still be nonzero,
	// if our first word and last words are the same.
	// create a bitmask in which only bits [start_idx_ge, end_idx_lt) are set.
	bitmap_word_t word;
	unsigned nbits = end_idx_lt - start_idx_ge;
	if (nbits < BITMAP_WORD_NBITS)
	{
		bitmap_word_t bitmask = 
			/* set bottom bits up to our end idx */
			BOTTOM_N_BITS_SET_T(bitmap_word_t, end_idx_lt) & 
			/* set top bits down to our start idx */
			TOP_N_BITS_SET_T(bitmap_word_t, BITMAP_WORD_NBITS - start_idx_ge)
			/* ANDed together... */
			;
		word = *p_startword & bitmask;
	} else word = *p_startword;
	count += popcount_word(word);
	return count;
}

static inline unsigned long nlz_l(bitmap_word_t w)
{
	return ntz(w);
}

static inline unsigned long ntz_l(bitmap_word_t w)
{
	return nlz(w);
}

static inline unsigned long bitmap_find_n_zero_l(bitmap_word_t *start_word, bitmap_word_t *bitmap_limit,
	unsigned long nbits)
{
	/* Assuming 64-bit words for the sake of an example....
	 * The most bits we can have with 0 fully zero words is 126.          The fewest is 0.
	 * The most bits we can have with 1 fully zero word  is 64 + 63 + 63. The fewest is 64.
	 * So what if I want 125 bits? I also need 0 fully zero words.
	 * So what if I want 129 bits? I also need 1 fully zero word.
	 *
	 * For this many bits  I need at least this many all-zero words     and at most this many.
	 * 0                   0                                            0
	 * 1 ..63              0                                            0
	 * 64..126             0                                            1
	 * 127                 1                                            1
	 * 128..190            1                                            2
	 * 191                 2                                            2
	 * 192..254            2                                            3
	 * 255                 3                                            3
	 * 256..               3                                            4
	 * ...
	 * The rightmost column is simply N / BITS_PER_WORD   - 1.
	 * The middle is N+65 / BITS_PER_WORD   - 2 ?
	 * In general... the minimum fully zero words is MAX(0, (nbits+ (WORD_NBITS+1) / WORD_NBITS) - 2)?
	 */
#ifndef MAX
#define MAX(a, b)  ((a) < (b) ? (b) : (a))
#endif
	int n_zero_words_minimum = MAX(
		( (int) nbits + ((int) BITMAP_WORD_NBITS + 1) ) / (int) BITMAP_WORD_NBITS   - 2,
		0);
	/* It is incomplete, but faster, to look for whole zero words.
	 * But HMM, this generalises: look for >=0 whole words with
	 * the necessary trailing bits *and* following bits or zero following word.
	 * So we can write one big loop. The first thing we do is look for
	 * a sequence of zero words, long enough to meet the minimum requirement,
	 * but where that length might be zero.
	 */
	bitmap_word_t *search_word = start_word;
	unsigned ntrailing = 0;
	while (search_word < bitmap_limit)
	{
		bitmap_word_t *zero_search_word = search_word;
		while (zero_search_word - search_word < n_zero_words_minimum
				&& zero_search_word < bitmap_limit
				&& !*zero_search_word) ++zero_search_word;
		if (zero_search_word - search_word == n_zero_words_minimum)
		{
			/* All cases that might possibly work satisfy the above condition.
			 *
			 * If we got here, then word at >= search_word and < zero_search_word form a continuous
			 * run of zero words. Do we have enough zero bits, using our trailing bits from the
			 * word before search_word? */
			if (ntrailing + BITMAP_WORD_NBITS * (zero_search_word - search_word)  >= nbits)
			{
				// success!
				return (search_word - start_word) * BITMAP_WORD_NBITS - ntrailing;
			}
			else if (zero_search_word == bitmap_limit) return (unsigned long) -1;
			else if (ntrailing + BITMAP_WORD_NBITS * (zero_search_word - search_word)
					+ nlz_l(*zero_search_word) >= nbits)
			{
				// success! using leading bits in the next word
				return (search_word - start_word) * BITMAP_WORD_NBITS - ntrailing;
			}
			else if (BITMAP_WORD_NBITS - popcount_word(*zero_search_word) >= nbits)
			{
				/* It *might* contain an internal string of zeroes... how to test efficiently? */
				assert(nbits < BITMAP_WORD_NBITS);
				for (unsigned i = 0; i < BITMAP_WORD_NBITS - nbits; ++i)
				{
					/* If we drop the leading i bits, do we have nlz >= nbits?
					 * Remember we are little-endian, so dropping the leading is least-sig... */
					if (nlz_l( (*zero_search_word) >> i )  >= nbits)
					{
						// ... success!
						return (zero_search_word - start_word) * BITMAP_WORD_NBITS + i;
					}
				}
			}
		}
		/* We fell down here because of the bitmap limit or because of a non-zero word.
		 * Either way, start searching again from the next word, but remembering the trailing
		 * zeroes. */
		search_word = zero_search_word + 1;
		ntrailing = ntz_l(*zero_search_word);
	}
	return (unsigned long) -1;
}
/* Some simple inline test cases for this */

#endif
