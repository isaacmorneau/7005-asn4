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
#include <omp.h>

#include "wrapper.h"

#define SOCKOPTS "p:a:e:dch"
#define MAXEVENTS 64

void print_help() {
    printf("usage options:\n"
            "\t [p]ort <1-65535>        - the port to listen to and forward to\n"
            "\t [a]ddress <url || ip>   - the address forward to\n"
            "\t [e]rror <percentage>    - the error rate to drop or corrupt\n"
            "\t [d]rop                  - drop packets\n"
            "\t [c]orrupt               - corrupt packets\n"
            "\t [h]elp                  - this message\n"
          );
}

int main(int argc, char ** argv) {
    char * port= 0;
    char * address = 0;
    //handle the arguments in its own scope
    {
        int c;
        for (;;) {
            int option_index = 0;

            static struct option long_options[] = {
                {"port",    required_argument, 0, 'p'},
                {"address", required_argument, 0, 'a'},
                {"error",   required_argument, 0, 'e'},
                {"drop",    no_argument,       0, 'd'},
                {"corrupt", no_argument,       0, 'c'},
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
                case 'a':
                    address = optarg;
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

#pragma omp parallel
    while (1) {
        int n, i;

        n = epoll_wait(efd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                // An error has occured on this fd, or the socket is not ready for reading
                // though its odd we were notified.
                fprintf (stderr, "epoll error\n");
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
                        outfd = make_connected(address, port);
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

                        event.events = EPOLLIN | EPOLLOUT | EPOLLET;

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
                    packet_read((epoll_data *)events[i].data.ptr, &pkt);
                    packet_send(((epoll_data *)events[i].data.ptr)->link, &pkt);
                }
            } else {
                //EPOLLOUT
                //shoulnt happen but this means we would have blocked
                //we are now notified that we can send the rest of the data
                flush_send((epoll_data *)event.data.ptr);
            }
        }
    }
    free(events);
    close(sfd);
    return 0;
}
