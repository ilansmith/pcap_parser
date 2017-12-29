#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "pcap.h"

enum time_presentation {
	SHOW_TIME,
	SHOW_TIME_EPOCH,
};

static void show_time(time_t ts_sec, uint32_t ts_usec)
{
	char timestamp[100];
	struct tm *tm;
	int tmp;

	tm = localtime((time_t*)(&ts_sec));
	strftime(timestamp, sizeof(timestamp), "%b %e, %Y %H:%M:%S", tm);
	tmp = strlen(timestamp);
	snprintf(timestamp + tmp, sizeof(timestamp) - tmp, ".%u", ts_usec);

	printf("%s  ", timestamp);
}

static void show_time_epoch(time_t ts_sec, uint32_t ts_usec)
{
	printf("%u.%u  ", (uint32_t)ts_sec, ts_usec);
}

static int do_next(enum time_presentation show)
{
	struct pcap buf;
	int ret;
	int i;
	void (*time_show)(time_t ts_sec, uint32_t ts_usec);

	ret = pcap_next(&buf);
	if (ret < 1) {
		if (!ret)
			printf("end of pcap\n");
		else
			printf("error reading pcap\n");

		return -1;
	}

	switch (show)
	{
	case SHOW_TIME:
		time_show = show_time;
		break;
	case SHOW_TIME_EPOCH:
		time_show = show_time_epoch;
		break;
	default:
		return -1;
	}

	time_show((time_t)read32(buf.hdr.ts_sec), read32(buf.hdr.ts_usec));
	for (i = 0; i < 14; i ++)
		printf(" %.2x", buf.data[i]);
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	int ret;

	ret = pcap_init("./capture.pcap");

	for (i = 0; !ret && i < 4; i++)
		ret = do_next(SHOW_TIME);

	pcap_uninit();
	return ret;
}

