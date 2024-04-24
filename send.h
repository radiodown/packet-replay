#ifndef SEND_H
#define SEND_H

int send_tcp(int port, char* host, char* data, int data_size);
void dump_hex(const void* data, int size);

#endif
