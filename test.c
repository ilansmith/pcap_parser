#include <stdint.h>
#include <stdio.h>

int pcap_init(char *pcap);
void pcap_uninit(void);

static void test_pcap_init(void)
{
	pcap_init("./capture.pcap");
}

static void test_pcap_uninit(void)
{
	pcap_uninit();
}

uint8_t read8(uint8_t var);
uint16_t read16(uint16_t var);
uint32_t read32(uint32_t var);
uint64_t read64(uint64_t var);

static void test_read(void)
{
	printf("read8(0xa3): 0x%x\n", read8(0xa3));
	printf("read16(0x2f1d): 0x%x\n", read16(0x2f1d));
	printf("read32(0xe529bd19): 0x%x\n", read32(0xe529bd19));
	printf("read64(0x6d9ea273b5f4c181): 0x%lx\n",
		read64(0x6d9ea273b5f4c181));
}

int pcap_next(void);

static void test_pcap_next(void)
{
	pcap_next();
	pcap_next();
	pcap_next();
	pcap_next();
}

int main(int argc, char **argv)
{
	test_pcap_init();
	test_read();
	test_pcap_next();
	test_pcap_uninit();

	return 0;
}

