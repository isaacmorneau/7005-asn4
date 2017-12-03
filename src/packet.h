/*
 * =====================================================================================
 *
 *       Filename:  packet.h
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  The raw packet structure for use in reading and writing
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:43:28 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */
#include <stdlib.h>

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
