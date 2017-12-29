#include <stdint.h>

#if defined (PCAP_DECLERATION)
#define MAKE_READ(sz) uint##sz##_t read##sz(uint##sz##_t var);
#elif defined(PCAP_IMPLEMENTATION)

static int is_swap_byte_order;

#define MAKE_READ(sz) \
uint##sz##_t read##sz(uint##sz##_t var) \
{ \
	static uint##sz##_t (*func[2])(uint##sz##_t var) = { \
		no_swap##sz, swap##sz \
	}; \
	return func[is_swap_byte_order](var); \
}

#define MAKE_NO_SWAP(sz) \
static uint##sz##_t no_swap##sz(uint##sz##_t var) \
{ \
	return var; \
}

MAKE_NO_SWAP(8)
MAKE_NO_SWAP(16)
MAKE_NO_SWAP(32)
MAKE_NO_SWAP(64)

static uint8_t swap8(uint8_t var)
{
	return var;
}

static uint16_t swap16(uint16_t var)
{
	return ((var & 0x00ff) << 8) |
		((var & 0xff00) >> 8);
}

static uint32_t swap32(uint32_t var)
{
	return ((var & 0x000000ff) << 24) |
		((var & 0x0000ff00) << 8) |
		((var & 0x00ff0000) >> 8) |
		((var & 0xff000000) >> 24);
}

static uint64_t swap64(uint64_t var)
{
	return ((var & 0x00000000000000ff) << 56) |
		((var & 0x000000000000ff00) << 40) |
		((var & 0x0000000000ff0000) << 24) |
		((var & 0x00000000ff000000) << 8) |
		((var & 0x000000ff00000000) >> 8) |
		((var & 0x0000ff0000000000) >> 24) |
		((var & 0x00ff000000000000) >> 40) |
		((var & 0xff00000000000000) >> 56);
}
#endif

MAKE_READ(8)
MAKE_READ(16)
MAKE_READ(32)
MAKE_READ(64)

#undef MAKE_READ
#undef PCAP_DECLERATION
#undef PCAP_IMPLEMENTATION

