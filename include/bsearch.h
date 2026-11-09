#ifndef BSEARCH_H_
#define BSEARCH_H_

/* NOTE: we use the GNU C "statement expressions" extension */

/* Macro which open-codes a binary search over a sorted array
 * of T, returning a pointer to the highest element that
 * is greater than or equal to the target. To get an integer
 * value out of a T t, we use proj(t). DO NOT USE 'return' in this macro!
 *
 * The code is also generic w.r.t. the >= and < operators The important thing is
 * that the array is sorted in <=-ascending order. */
#define /* T* */  bsearch_leq_generic_w_op(T, target_proj_val, /*  T*  */ base, \
  /* unsigned */ n, proj, LEQ) \
	({ \
		T *upper = base + n; \
		T *lower = base; \
		T *ret = NULL; \
		if (upper - lower == 0) abort(); \
		if (proj(lower) LEQ target_proj_val) \
		{ \
			while (upper - lower != 1) \
			{ \
				T *mid = lower + ((upper - lower) / 2); \
				if (!(proj(mid) LEQ target_proj_val)) \
				{ \
					/* we should look in the lower half */ \
					upper = mid; \
				} \
				else lower = mid; \
			} \
			assert(proj(lower) LEQ target_proj_val); \
			/* if we didn't hit the max item, assert the next one is greater */ \
			assert(lower == base + n - 1 \
				 || !(proj(lower+1) LEQ target_proj_val)); \
			/* If all elements are > the target, return NULL */ \
			ret = (proj(lower) LEQ target_proj_val) ? lower : NULL; \
		} \
		ret; \
	})
#define /* T* */  bsearch_leq_generic(T, target_proj_val, /*  T*  */ base, /* unsigned */ n, proj) \
  bsearch_leq_generic_w_op(T, target_proj_val, /*  T*  */ base, \
  /* unsigned */ n, proj, <=)

#endif
