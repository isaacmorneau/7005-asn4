#ifndef WRAPPER_H
#define WRAPPER_H
#include "../packet.h"

typedef struct epoll_data_T {
    int fd;
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

