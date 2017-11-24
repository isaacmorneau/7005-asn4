#ifndef PACKET_H
#define PACKET_H

#define PACKET_MAX_LEN 1074
#define PACKET_MAX_DATA 1072
#define PACKET_CIPHER 1024
#define PACKET_IV 16
#define PACKET_HMAC 32


typedef struct raw_packet {
    unsigned short length; //first two bytes
    unsigned char data[PACKET_MAX_DATA];
} raw_packet;

#endif
