#undef NDEBUG
#include <assert.h>
#include "bitmap.h"

/* bitmap words have the same width as uintptr_t / intptr_t */
#if __INTPTR_WIDTH__ == 64

/* Thank you camel-cdr: https://stackoverflow.com/questions/74723697/how-to-concatenate-all-of-the-arguments-of-a-variadic-macro-into-a-quoted-string */
#define CAT_(a,b,c,d,e,f,g,i,j,k,l,m,n,o,p,...) a##b##c##d##e##f##g##i##j##k##l##m##n##o##p
#define CAT(...) CAT_(__VA_ARGS__,,,,,,,,,,,,,,,,,)

/* We want a syntax like 0b0000_1111, with the underscore to separate digits.
 * Even GCC does not give this to us. So let's make it. We still rely on the
 * GCC extension for binary literals. We use comma, not underscore. */
#define bits(suff, first, ...) CAT( 0b ## first, CAT(__VA_ARGS__), suff)

/* Now we need a list-mapping macro function...
 * based on map-macro by William R Swanson, CC0 1.0 Universal a.k.a. public domain.
 * https://github.com/swansontec/map-macro
 * https://creativecommons.org/publicdomain/zero/1.0/
 */
#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0(EVAL0(EVAL0(__VA_ARGS__)))
#define EVAL2(...) EVAL1(EVAL1(EVAL1(__VA_ARGS__)))
#define EVAL3(...) EVAL2(EVAL2(EVAL2(__VA_ARGS__)))
#define EVAL4(...) EVAL3(EVAL3(EVAL3(__VA_ARGS__)))
#define EVAL5(...) EVAL4(EVAL4(EVAL4(__VA_ARGS__)))
#define EVAL(...)  EVAL5(__VA_ARGS__)

#define MAP_END(...)
#define MAP_OUT

#define EMPTY()
#define DEFER(id) id EMPTY()

#define MAP_GET_END2() 0, MAP_END
#define MAP_GET_END1(...) MAP_GET_END2
#define MAP_GET_END(...) MAP_GET_END1
#define MAP_NEXT0(test, next, ...) next MAP_OUT
#define MAP_NEXT1(test, next) DEFER ( MAP_NEXT0 ) ( test, next, 0)
#define MAP_NEXT(test, next)  MAP_NEXT1(MAP_GET_END test, next)

#define MAP_LIST0(f, x, peek, ...) , f(x) DEFER ( MAP_NEXT(peek, MAP_LIST1) ) ( f, peek, __VA_ARGS__ )
#define MAP_LIST1(f, x, peek, ...) , f(x) DEFER ( MAP_NEXT(peek, MAP_LIST0) ) ( f, peek, __VA_ARGS__ )
#define MAP_LIST2(f, x, peek, ...)   f(x) DEFER ( MAP_NEXT(peek, MAP_LIST1) ) ( f, peek, __VA_ARGS__ )

/**
 * Applies the function macro `f` to each of the remaining parameters and
 * inserts commas between the results.
 */
#define MAP_LIST(f, ...) EVAL(MAP_LIST2(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/* Test for bitmap_find_n_zero_l.
 *
 * This treats word little-endianly, so we ned to do some bitwise reversal.
 * In other words, the leftmost bits, as written in the bits(...) macro invocations below,
 * are actually the *least* significant of the word. */

/* This macro letsus bitwise-reverse all words in an arbitrarily long initializer list. */
#define bitwise_reverse_all(...)  MAP_LIST( bitrev64, __VA_ARGS__ )

/* Now we can define test cases in one line, in a convenient notation. */
#define bitmap_find_n_zero_l_test_case( n, result, bitmap_literal... ) do { \
     bitmap_word_t bits[] = { bitwise_reverse_all(bitmap_literal) }; \
     bitmap_word_t *limit = &bits[0] + (sizeof bits / sizeof bits[0]); \
     assert( (result) == bitmap_find_n_zero_l(&bits[0], limit, (n))); } while(0)

int main(void)
{
	bitmap_find_n_zero_l_test_case(0,  0, bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(1,  0, bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(63, 0, bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(64, 0, bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(65, -1, bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));

	bitmap_find_n_zero_l_test_case(65, 1,  bits(ull,1000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000), bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(65, 63, bits(ull,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1110), bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));

	bitmap_find_n_zero_l_test_case(65, 65, bits(ull,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111), bits(ull,1000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000), bits(ull,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000));
	bitmap_find_n_zero_l_test_case(66, -1, bits(ull,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111), bits(ull,1000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000), bits(ull,0011,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111));

	bitmap_find_n_zero_l_test_case(4, 5, bits(ull,1111,1000,0111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111));
	bitmap_find_n_zero_l_test_case(4, 5, bits(ull,1011,1000,0011,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111));
	bitmap_find_n_zero_l_test_case(4, 5, bits(ull,1011,1000,0011,1111,1111,1111,1111,1111,0000,1111,1111,1111,1111,1111,1111,1111));

	bitmap_find_n_zero_l_test_case(1, -1, bits(ull,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111,1111));

}

#else
#warning "No bitmap test for 32-bit builds, unfortunately (FIXME)"
#endif
