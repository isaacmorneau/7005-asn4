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
        //read max standard pipe allocation size
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
int packet_send(epoll_data * epd, raw_packet * packet) {
    int nr;
    if ((nr = write(epd->pipefd[1], packet, packet->length)) == -1) {
        if (nr <= 0) {
            //this should never happen, its moving a packet into the pipe buffer
            if (errno != EAGAIN) {
                perror("write");
                return -1;
            }
            return -2;
        }
    }
    for (;;) {
        nr = splice(epd->pipefd[0], 0, epd->fd, 0, USHRT_MAX, SPLICE_F_MOVE | SPLICE_F_MORE);
        if (nr <= 0) {
            if (nr == -1 && errno != EAGAIN) {
                perror("splice");
                return -3;
            }
            break;
        }
    }
    return 0;
}

int flush_send(epoll_data * epd) {
    for (;;) {
        int ret = splice(epd->pipefd[0], 0, epd->fd, 0, USHRT_MAX, SPLICE_F_MOVE | SPLICE_F_MORE);
        if (ret <= 0) {
            if (ret == -1 && errno != EAGAIN) {
                perror("splice");
                return -1;
            }
            break;
        }
    }
    return 0;
}

void epoll_data_close(epoll_data * epd) {
    close(epd->pipefd[0]);
    close(epd->pipefd[1]);
    close(epd->fd);
}

int epoll_data_init(epoll_data * epd, int fd) {
    epd->fd = fd;
    if (pipe(epd->pipefd)) {
        perror("pipe");
        return 1;
    }
    return 0;
}
