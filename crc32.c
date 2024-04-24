#include "crc32.h"
#include "syshead.h"
#include "pcap.h"

uint32_t crc32_calc(uint8_t *data, int len)
{
	int i, j;
	uint32_t crc;

	if (!data)
		return 0;

	if (len < 1)
		return 0;

	crc = 0xFFFFFFFF;

	for (j = 0; j < len; j++)
	{
		crc ^= data[j];

		for (i = 0; i < 8; i++)
		{
			crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320) : (crc >> 1);
		}
	}

	return (crc ^ 0xFFFFFFFF);
}

int has_crc32(TCP_SESSION *session)
{
	uint32_t frame_fcs = (session->raw[session->pcap->orig_len - 1] << 24) |
						 (session->raw[session->pcap->orig_len - 2] << 16) |
						 (session->raw[session->pcap->orig_len - 3] << 8) |
						 session->raw[session->pcap->orig_len - 4];

	uint32_t calc_fcs = crc32_calc(session->raw, session->pcap->orig_len - 4);

	return frame_fcs == calc_fcs;
}