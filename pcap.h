#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdint.h>

struct pcaprec_hdr {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
};

struct pcap {
	struct pcaprec_hdr hdr;
	uint8_t *data;
};

int pcap_init(char *pcap_path);
int pcap_next(struct pcap *buf);
void pcap_uninit(void);

#define PCAP_DECLERATION
/*
 * uint8_t read8(uint8_t var);
 * uint16_t read16(uint16_t var);
 * uint32_t read32(uint32_t var);
 * uint64_t read64(uint64_t var);
 */
#include "pcap_read.h"

#endif

