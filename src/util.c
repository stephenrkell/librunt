#include <stdint.h>

__attribute__((visibility("hidden")))
const char *fmt_hex_num(uint64_t n)
{
	static char buf[19]; // FIXME: check if a problem to make this thread-local?
	buf[0] = '0';
	buf[1] = 'x';
	signed i_dig = 15;
	do
	{
		unsigned long dig = (n >> (4 * i_dig)) & 0xf;
		buf[2 + 15 - i_dig] = (dig > 9) ? ('a' + dig - 10) : ('0' + dig);
		--i_dig;
	} while (i_dig >= 0);
	buf[18] = '\0';
	return buf;
}

#if 0
__attribute__((visibility("hidden")))
const char *fmt_hex_num_with_bitwidth(uint64_t n, unsigned width_nbits)
{
	static char buf[35]; // FIXME: check if a problem to make this thread-local?
	buf[0] = '0';
	buf[1] = 'x';
	unsigned pos = 2;
	signed i_dig = width_nbits % 4 == 0 ? width_nbits / 4 : 1 + (width_nbits / 4);
	if (i_dig > 31) i_dig = 31;
	do
	{
		unsigned long long dig = (n >> (4 * i_dig)) & 0xf;
		buf[pos++] = (dig > 9) ? ('a' + dig - 10) : ('0' + dig);
		--i_dig;
	} while (i_dig >= 0);
	buf[pos] = '\0';
	return buf;
}
#endif
