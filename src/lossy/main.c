/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *        Project:  7005-asn4-lossy
 *
 *    Description:  This file is the implementation of the lossy server's command parsing
 *                  and epoll implementation.
 *
 *      Functions:  print_help();
 *                  __iter_div_u64_rem();
 *                  timespec_add_ns();
 *                  main();
 *
 *
 *        Version:  1.0
 *        Created:  12/02/2017 03:27:32 PM
 *       Revision:  none
 *
 *         Author:  Isaac Morneau (im), isaacmorneau@gmail.com
 *
 * =====================================================================================
 */
#include <stdlib.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>

#include "wrapper.h"
#include "errors.h"

#define SOCKOPTS "p:f:t:a:e:h"

#define MAXEVENTS 64

#define ERROR_DROP 0
#define ERROR_BER 1
#define ERROR_WAIT 2

#define MICRO_IN_SEC 1000ul * 1000ul
#define NANO_IN_SEC 1000ul * MICRO_IN_SEC

static inline void print_help() {
    printf("usage options:\n"
            "\t [p]ort <1-65535>                    - the port to listen to\n"
            "\t [f]orward <1-65535>                 - the port to forward to\n"
            "\t [a]ddress <url || ip>               - the address forward to\n"
            "\t [e]rror <percentage>                - the error rate, default is no errors\n"
            "\t [t]ype <D || B || W[microseconds]>  - the type of error to have\n"
            "\t\t D is to drop packets, default type\n"
            "\t\t B is BER to corrupt packets in percent such as B5.0\n"
            "\t\t W is time to wait in microseconds such as W100\n"
            "\t [h]elp                  - this message\n"
          );
}


//thanks https://eastskykang.wordpress.com/2015/03/24/138/
static inline uint32_t __iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder) {
    uint32_t ret = 0;
    while (dividend >= divisor) {
        /* The following asm() prevents the compiler from
           optimising this loop into a modulo operation.  */
        __asm__("": "+rm"(dividend));
        dividend -= divisor;
        ret++;
    }
    *remainder = dividend;
    return ret;
}

static inline void timespec_add_ns(struct timespec *a, uint64_t ns) {
    a->tv_sec += __iter_div_u64_rem(a->tv_nsec + ns, NANO_IN_SEC, &ns);
    a->tv_nsec = ns;
}

int main(int argc, char ** argv) {
    char * port= 0;
    char * forward = 0;
    char * address = 0;
    char * drop = 0;

    int handshake_delay = 4;
    int error_type = 0;
    int delay = 0;
    struct timespec time_to_wait;
    int BER_rate = 0, BER_loop = 1;
    errors er;
    er.loop = -1;

    //handle the arguments in its own scope
    {
        int c;
        for (;;) {
            int option_index = 0;

            static struct option long_options[] = {
                {"port",    required_argument, 0, 'p'},
                {"forward", required_argument, 0, 'f'},
                {"address", required_argument, 0, 'a'},
                {"error",   required_argument, 0, 'e'},
                {"type",    required_argument, 0, 't'},
                {"help",    no_argument,       0, 'h'},
                {0,         0,                 0, 0}
            };

            c = getopt_long(argc, argv, SOCKOPTS, long_options, &option_index);
            if (c == -1) {
                break;
            }

            switch (c) {
                case 'p':
                    port = optarg;
                    break;
                case 'f':
                    forward = optarg;
                    break;
                case 'a':
                    address = optarg;
                    break;
                case 'e':
                    drop = optarg;
                    errors_init(&er, drop);
                    break;
                case 't':
                    switch (*optarg) {
                        case 'B':
                            error_type = ERROR_BER;
                            if (optarg[1] == '\0') {
                                print_help();
                                return 1;
                            }
                            dec_to_frac(optarg+1, &BER_rate, &BER_loop);
                            break;
                        case 'W':
                            error_type = ERROR_WAIT;
                            if (optarg[1] == '\0') {
                                print_help();
                                return 1;
                            }
                            delay = atoi(optarg+1);
                            break;
                        case 'D':
                        default:
                            error_type = ERROR_DROP;
                            break;
                    }
                    break;
                case 'h':
                case '?':
                default:
                    print_help();
                    return 0;
            }
        }
        if (!port || !address) {
            print_help();
            return 1;
        }
        if (!forward) {
            forward = port;
        }
    }

    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;
    epoll_data * data;
    //make and bind the socket
    sfd = make_bound(port);
    if (sfd == -1) {
        return 2;
    }

    //start listening
    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        return 3;
    }

    //register the epoll structure
    efd = epoll_create1(0);
    if (efd == -1) {
        perror ("epoll_create1");
        return 4;
    }

    data = calloc(1, sizeof(epoll_data));
    epoll_data_init(data, sfd);
    event.data.ptr = data;
    event.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        return 5;
    }

    // Buffer where events are returned (no more that 64 at the same time)
    events = calloc(MAXEVENTS, sizeof(event));

    while (1) {
        int n, i;

        n = epoll_wait(efd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                //connection closed
                epoll_data_close(((epoll_data *)events[i].data.ptr)->link);
                free(((epoll_data *)events[i].data.ptr)->link);
                epoll_data_close((epoll_data *)events[i].data.ptr);
                free(events[i].data.ptr);
                continue;
            } else if((events[i].events & EPOLLIN)) {
                if (sfd == ((epoll_data *)events[i].data.ptr)->fd) {
                    // We have a notification on the listening socket, which
                    // means one or more incoming connections.
                    while (1) {
                        struct sockaddr in_addr;
                        socklen_t in_len;
                        int infd, outfd;
                        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                        epoll_data * in_data;
                        epoll_data * out_data;

                        in_len = sizeof in_addr;
                        infd = accept(sfd, &in_addr, &in_len);
                        if (infd == -1) {
                            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                                // We have processed all incoming
                                // connections.
                                break;
                            } else {
                                perror("accept");
                                break;
                            }
                        }

                        s = getnameinfo(&in_addr, in_len, hbuf, sizeof hbuf, sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV);
                        if (s == 0) {
                            printf("Accepted connection on descriptor %d "
                                    "(host=%s, port=%s)\n", infd, hbuf, sbuf);
                        }
                        outfd = make_connected(address, forward);
                        if (outfd == -1) {
                            fprintf(stderr, "Failed to establish bridged connection\n");
                            close(infd);
                            continue;
                        }

                        // Make the incoming socket non-blocking and add it to the
                        // list of fds to monitor.
                        s = make_non_blocking(infd);
                        if (s == -1) {
                            abort();
                        }
                        s = make_non_blocking(outfd);
                        if (s == -1) {
                            abort();
                        }

                        //create the epoll structures
                        in_data = calloc(1, sizeof(epoll_data));
                        out_data = calloc(1, sizeof(epoll_data));
                        epoll_data_init(in_data, infd);
                        epoll_data_init(out_data, outfd);
                        //link the bridged connections
                        in_data->link = out_data;
                        out_data->link = in_data;

                        event.events = EPOLLIN | EPOLLOUT;

                        event.data.ptr = in_data;
                        s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
                        if (s == -1) {
                            perror("epoll_ctl");
                            abort();
                        }
                        event.data.ptr = out_data;
                        s = epoll_ctl(efd, EPOLL_CTL_ADD, outfd, &event);
                        if (s == -1) {
                            perror("epoll_ctl");
                            abort();
                        }
                    }
                    continue;
                } else {
                    //read in the length of the packet and then the rest of the packet and loop on reading packets to ensure you got them all
                    //then drop the ones due to the error rates
                    //then send the rest on to the other side
                    raw_packet pkt;
                    if (packet_read((epoll_data *)events[i].data.ptr, &pkt) == 1) {
                        if (handshake_delay-- > 0 || !errors_checkdrop(&er)) {
                            packet_send(((epoll_data *)events[i].data.ptr)->link, &pkt);
                            printf("packet sent %d: %d->%d\n", pkt.length, ((epoll_data *)events[i].data.ptr)->fd, ((epoll_data *)events[i].data.ptr)->link->fd);
                        } else {
                            switch (error_type) {
                                case ERROR_DROP:
                                    printf("packet dropped %d: %d->%d\n", pkt.length, ((epoll_data *)events[i].data.ptr)->fd, ((epoll_data *)events[i].data.ptr)->link->fd);
                                    break;
                                case ERROR_WAIT:
                                    //I hate using sleeps but for a blocking wait theres not a better alternative
                                    //if you grep for this again im sorry to use it.
                                    printf("packet delayed %d: %d->%d\n", pkt.length, ((epoll_data *)events[i].data.ptr)->fd, ((epoll_data *)events[i].data.ptr)->link->fd);

                                    clock_gettime(CLOCK_REALTIME, &time_to_wait);
                                    timespec_add_ns(&time_to_wait, delay);
                                    nanosleep(&time_to_wait, 0);
                                    packet_send(((epoll_data *)events[i].data.ptr)->link, &pkt);
                                    break;
                                case ERROR_BER:
                                    printf("packet corrupted %d: %d->%d\n", pkt.length, ((epoll_data *)events[i].data.ptr)->fd, ((epoll_data *)events[i].data.ptr)->link->fd);
                                    damage_packet(&pkt, BER_rate, BER_loop);
                                    packet_send(((epoll_data *)events[i].data.ptr)->link, &pkt);
                                    break;
                            }
                        }
                    }
                }
            }
        }
    }
    errors_close(&er);
    free(events);
    close(sfd);
    return 0;
}
