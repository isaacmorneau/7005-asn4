/*
 * =====================================================================================
 *
 *       Filename:  wrapper.h
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  The wrappers for the network interaction with epoll
 *
 *      Functions:  make_bound();
 *                  make_connected();
 *                  make_non_blocking();
 *                  packet_read();
 *                  packet_send();
 *                  epoll_data_init();
 *                  epoll_data_close()
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:41:45 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */

#ifndef WRAPPER_H
#define WRAPPER_H
#include "../packet.h"
#include "errors.h"

typedef struct epoll_data_T {
    int fd;
    errors er;
    struct epoll_data_T * link;
} epoll_data;

int make_bound(const char * port);
int make_non_blocking(int sfd);
int make_connected(const char * address, const char * port);
int packet_send(epoll_data * epd, raw_packet * packet);
int packet_read(epoll_data * epd, raw_packet * packet);
int flush_send(epoll_data * epd);
//close all the members
void epoll_data_close(epoll_data * epd);
//initialize the pip and set the fd
int epoll_data_init(epoll_data * epd, int fd);

#endif //WRAPPER_H

