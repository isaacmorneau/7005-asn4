/*
 * =====================================================================================
 *
 *       Filename:  wrapper.c
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  The wrappers for interacting with the networking for epoll
 *
 *      Functions:  make_bound();
 *                  make_connected();
 *                  make_non_blocking();
 *                  packet_read();
 *                  packet_send();
 *                  epoll_data_init();
 *                  epoll_data_close()
 *
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:40:00 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */
#include <stdlib.h>

#define _GNU_SOURCE
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <limits.h>

#include "wrapper.h"
#include "../packet.h"

#define BUFFSIZE 1024

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  make_bound
 *  Description:  bind to port in char string
 *   Parameters:  const char * port - the string of the port to bind to
 *       Return:  int - the fd of the socket or -1 for error
 * =====================================================================================
 */
int make_bound(const char * port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     // Return IPv4 and IPv6 choices
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags = AI_PASSIVE;     // All interfaces

    s = getaddrinfo(0, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror (s));
        return -1;
    }

    for (rp = result; rp != 0; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }
        int enable = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1) {
            perror("Socket options failed");
            exit(EXIT_FAILURE);
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            // We managed to bind successfully!
            break;
        }

        close(sfd);
    }

    if (!rp) {
        fprintf(stderr, "Unable to bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  make_connected
 *  Description:  makes a socket connected to the address and port
 *   Parameters:  const char * address - the address to connect to
 *                const char * port - the port to connect to
 *       Return:  int - the connected socket or -1 for error
 * =====================================================================================
 */
int make_connected(const char * address, const char * port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     // Return IPv4 and IPv6 choices
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags = AI_PASSIVE;     // All interfaces

    s = getaddrinfo(address, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror (s));
        return -1;
    }

    for (rp = result; rp != 0; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        s = connect(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            break;
        }

        close(sfd);
    }

    if (!rp) {
        fprintf(stderr, "Unable to connect\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  make_non_blocking
 *  Description:  makes the fd non blocking
 *   Parameters:  int sfd - the fd to change
 *       Return:  int - -1 for failure
 * =====================================================================================
 */
int make_non_blocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1){
        perror("fcntl get");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl set");
        return -1;
    }

    return 0;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  packet_read
 *  Description:  read in 1 packets worth of data from an epoll struct
 *   Parameters:  epoll_data * epd - the struct to read from
 *                raw_packet * packet - the packet to store it in
 *       Return:  int  - -1 for error; 0 for no data; 1 for success
 * =====================================================================================
 */
int packet_read(epoll_data * epd, raw_packet * packet) {
    int nr;
    if ((nr = read(epd->fd, &(packet->length), 2)) == -1) {
        if (nr <= 0) {
            if (errno != EAGAIN) {
                perror("read");
                return -1;
            }
            return 0;//nothing to read at all just say theres nothing
        }
    }
    int len = 0;
    while (len < packet->length - 2) {
        nr = read(epd->fd, packet->data + len, packet->length - 2 - len);
        if (nr <= 0) {
            if (errno != EAGAIN) {
                perror("read");
                return -2;
            }
            break;
        }
        len += nr;
    }
    return 1;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  packet_send
 *  Description:  sends 1 packet of data to the epoll structure
 *   Parameters:  epoll_data * epd - the struct to write to
 *                raw_packet * packet - the packet to send
 *       Return:  int  - -1 for error; 0 for success
 * =====================================================================================
 */
int packet_send(epoll_data * epd, raw_packet * packet) {
    int nr;
    for (int len = packet->length;len;) {
        nr = write(epd->fd, packet, packet->length);
        if (nr <= 0) {
            if (nr == -1 && errno != EAGAIN) {
                perror("write");
                return -1;
            }
            break;
        }
        len -= nr;
    }
    return 0;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  epoll_data_close
 *  Description:  close the epoll structure
 *   Parameters:  epoll_data * epd - the struct to close
 *       Return:  void
 * =====================================================================================
 */
void epoll_data_close(epoll_data * epd) {
    close(epd->fd);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  epoll_data_init
 *  Description:  initialze the epoll structure
 *   Parameters:  epoll_data * epd - the struct to initialze
 *                int fd - the fd to set to the struct
 *       Return:  int - 0 for success
 * =====================================================================================
 */
int epoll_data_init(epoll_data * epd, int fd) {
    epd->fd = fd;
    return 0;
}
