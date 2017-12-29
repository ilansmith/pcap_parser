#include <stdlib.h>
#include <stdio.h>
#include "pcap.h"

#define PCAP_IMPLEMENTATION
#include "pcap_read.h"

struct pcap_hdr {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};

static uint8_t *data = NULL;
static FILE *fpcap;

int pcap_init(char *pcap_path)
{
	struct pcap_hdr hdr;
	int ret = -1;

	fpcap = fopen(pcap_path, "r");
	if (!fpcap)
		goto err;

	ret = fread(&hdr, sizeof(struct pcap_hdr), 1, fpcap);
	if (!ret) {
		ret = -1;
		goto err;
	}

	switch (hdr.magic_number) {
	case 0xa1b2c3d4:
		is_swap_byte_order = 0;
		break;
	case 0xd4c3b2a1:
		is_swap_byte_order = 1;
		break;
	default:
		goto err;
		break;
	}

	if (read16(hdr.version_major) != 2 || read16(hdr.version_minor) != 4)
		goto err;

	data = calloc(1, read32(hdr.snaplen));
	if (!data)
		goto err;

	return 0;

err:
	pcap_uninit();
	return -1;
}

int pcap_next(struct pcap *buf)
{
	int ret;
	struct pcaprec_hdr hdr;
	int incl_len;

	ret = fread(&hdr, sizeof(struct pcaprec_hdr), 1, fpcap);
	if (!ret)
		return 0;

	incl_len = read32(hdr.incl_len);
	ret = fread(data, sizeof(uint8_t), incl_len, fpcap);
	if (ret != incl_len)
		return -1;

	buf->hdr = hdr;
	buf->data = data;

	return incl_len;
}

void pcap_uninit(void)
{
	if (fpcap)
		fclose(fpcap);
	free(data);
}

