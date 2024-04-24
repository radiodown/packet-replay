#ifndef CRC32_H
#define CRC32_H

#include "pcap.h"

/* Calc crc32 for FCS */
uint32_t crc32_calc(uint8_t *data, int len);

int has_crc32(TCP_SESSION *session);

#endif