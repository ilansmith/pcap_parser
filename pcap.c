#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifdef CONFIG_DEBUG
#define STATIC
#else
#define STATIC static
#endif

#define MAKE_NO_SWAP(sz) \
static uint##sz##_t no_swap##sz(uint##sz##_t var) \
{ \
	return var; \
}

#define MAKE_READ(sz) \
STATIC uint##sz##_t read##sz(uint##sz##_t var) \
{ \
	static uint##sz##_t (*func[2])(uint##sz##_t var) = { \
		no_swap##sz, swap##sz \
	}; \
	return func[is_swap_byte_order](var); \
}

struct pcap_hdr {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};

struct pcaprec_hdr {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
};

static int is_swap_byte_order;
static uint8_t *buf;
static FILE *fpcap;

MAKE_NO_SWAP(8);
MAKE_NO_SWAP(16);
MAKE_NO_SWAP(32);
MAKE_NO_SWAP(64);

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

MAKE_READ(8);
MAKE_READ(16);
MAKE_READ(32);
MAKE_READ(64);

static int pcap_hdr_read(struct pcap_hdr *hdr)
{
	return fread(hdr, sizeof(struct pcap_hdr), 1, fpcap) == 1 ? 0 : -1;
}

void pcap_uninit(void)
{
	if (fpcap)
		fclose(fpcap);
	free(buf);

	fpcap = NULL;
	buf = NULL;
}

int pcap_init(char *pcap)
{
	struct pcap_hdr hdr;
	int ret;

	if (!(fpcap = fopen(pcap, "r")))
		goto exit;

	ret = pcap_hdr_read(&hdr);
	if (ret)
		goto exit;

	switch (hdr.magic_number) {
	case 0xa1b2c3d4:
		is_swap_byte_order = 0;
		break;
	case 0xd4c3b2a1:
		is_swap_byte_order = 1;
		break;
	default:
		break;
	}

	if (read16(hdr.version_major) != 2 || read16(hdr.version_minor) != 4)
		goto exit;

	buf = calloc(1, read32(hdr.snaplen));
	if (!buf)
		goto exit;

	return 0;

exit:
	pcap_uninit();
	return -1;
}

int pcap_next(void)
{
	int ret;
	struct pcaprec_hdr hdr;
	int incl_len;

	ret = fread(&hdr, sizeof(struct pcaprec_hdr), 1, fpcap);
	if (!ret)
		return 0;

	incl_len = read32(hdr.incl_len);
	ret = fread(buf, sizeof(uint8_t), incl_len, fpcap);
	if (ret != incl_len)
		return -1;

	return incl_len;
}

