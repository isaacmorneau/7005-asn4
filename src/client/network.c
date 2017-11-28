/*
 *Copyright (C) 2017 John Agapeyev
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation, either version 3 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License
 *along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *cryptepoll is licensed under the GNU General Public License version 3
 *with the addition of the following special exception:
 *
 ***
 In addition, as a special exception, the copyright holders give
 permission to link the code of portions of this program with the
 OpenSSL library under certain conditions as described in each
 individual source file, and distribute linked combinations
 including the two.
 You must obey the GNU General Public License in all respects
 for all of the code used other than OpenSSL.  If you modify
 file(s) with this exception, you may extend this exception to your
 version of the file(s), but you are not obligated to do so.  If you
 do not wish to do so, delete this exception statement from your
 version.  If you delete this exception statement from all source
 files in the program, then also delete it here.
 ***
 *
 */
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "network.h"
#include "epoll.h"
#include "socket.h"
#include "crypto.h"
#include "macro.h"
#include "main.h"

EVP_PKEY *LongTermSigningKey = NULL;
bool isServer;
struct client *clientList;
size_t clientCount;
unsigned short port;
int listenSock;

pthread_mutex_t clientLock;
pthread_cond_t cv;
bool ackReceived = false;

#define MICRO_IN_SEC 1000ul * 1000ul
#define NANO_IN_SEC 1000ul * MICRO_IN_SEC

#define TIMEOUT_NS 700ul * MICRO_IN_SEC
#define MAX_RETRIES 10

struct timespec timeToWait;

void network_init(void) {
    _Static_assert(TIMEOUT_NS < NANO_IN_SEC, "Packet timeout value must be less than the number of nanoseconds in one second");
    initCrypto();
    LongTermSigningKey = generateECKey();
    clientList = checked_calloc(10, sizeof(struct client));
    clientCount = 1;
    pthread_mutex_init(&clientLock, NULL);
    pthread_cond_init(&cv, NULL);
}

void network_cleanup(void) {
    if (LongTermSigningKey) {
        EVP_PKEY_free(LongTermSigningKey);
    }
    for (size_t i = 0; i< clientCount; ++i) {
        OPENSSL_clear_free(clientList[i].sharedKey, SYMMETRIC_KEY_SIZE);
        EVP_PKEY_free(clientList[i].signingKey);
    }
    pthread_mutex_destroy(&clientLock);
    pthread_cond_destroy(&cv);
    free(clientList);
    cleanupCrypto();
}

/*
 * Does nothing intentionally.
 * This is to be replaced by the application's desired behaviour
 */
void process_packet(const unsigned char * const buffer, const size_t bufsize, struct client *src) {
    //Used to remove warnings about unused parameters
    (void)(buffer);
    (void)(bufsize);

    if (buffer[0] == ACK) {
        pthread_mutex_lock(&clientLock);

        uint16_t ackVal;
        //Grab ack value from buffer
        memcpy(&ackVal, buffer + 3, sizeof(uint16_t));

        if (ackVal == src->seq) {
            //Received ack for a packet
            ackReceived = true;
            pthread_cond_broadcast(&cv);
        } else {
            //Received ack for older packet, or weird error, so ignore
        }
        pthread_mutex_unlock(&clientLock);
    }

#ifndef NDEBUG
    printf("Received packet of size %zu\n", bufsize);
    debug_print_buffer("Raw hex output: ", buffer, bufsize);

    printf("\nText output: ");
    for (size_t i = 0; i < bufsize; ++i) {
        printf("%c", buffer[i]);
    }
    printf("\n");

    PacketType type = *buffer;
    uint16_t seq = ((uint16_t *)(buffer + 1))[0];
    uint16_t ack = ((uint16_t *)(buffer + 1))[1];
    uint16_t winSize = ((uint16_t *)(buffer + 1))[2];

    printf("Packet Control Values:\n");
    printf("Type: %d\nSeq: %d\nAck: %d\nWindow Size: %d\n", type, seq, ack, winSize);

    printf("Packet contents stripped of headers: ");
    for (size_t i = 0 ; i < bufsize - 7; ++i) {
        printf("%c", buffer[i + 7]);
    }
    printf("\n");

#endif
}

/*
 * Server signing key
 * Server public key + hmac
 * Client signing key
 * Client public key + hmac
 */
unsigned char *exchangeKeys(const int * const sock) {
    size_t pubKeyLen;
    unsigned char *signPubKey = getPublicKey(LongTermSigningKey, &pubKeyLen);

    EVP_PKEY *ephemeralKey = generateECKey();
    size_t ephemeralPubKeyLen;
    unsigned char *ephemeralPubKey = getPublicKey(ephemeralKey, &ephemeralPubKeyLen);

    size_t hmaclen = 0;
    unsigned char *hmac = generateHMAC_Buffer(ephemeralPubKey, ephemeralPubKeyLen, &hmaclen, signPubKey, pubKeyLen);

    unsigned char *sharedSecret = NULL;

    struct client *clientEntry = container_entry(sock, struct client, socket);

    if (isServer) {
        sendSigningKey(*sock, signPubKey, pubKeyLen);
        sendEphemeralKey(*sock, clientEntry, ephemeralPubKey, ephemeralPubKeyLen, hmac, hmaclen);
        readSigningKey(*sock, clientEntry, pubKeyLen);

        uint16_t packetLength = ephemeralPubKeyLen + hmaclen + sizeof(uint16_t) + sizeof(uint16_t);
        unsigned char *mesgBuffer = checked_malloc(packetLength);

        if (!receiveAndVerifyKey(sock, mesgBuffer, packetLength, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *clientPubKey = setPublicKey(mesgBuffer + sizeof(uint16_t) + sizeof(uint16_t), ephemeralPubKeyLen);

        clientEntry->ack = *((uint16_t *)(mesgBuffer + sizeof(uint16_t)));

        sharedSecret = getSharedSecret(ephemeralKey, clientPubKey);

        EVP_PKEY_free(clientPubKey);
        free(mesgBuffer);
    } else {
        readSigningKey(*sock, clientEntry, pubKeyLen);

        uint16_t packetLength = ephemeralPubKeyLen + hmaclen + sizeof(uint16_t) + sizeof(uint16_t);

        unsigned char *mesgBuffer = checked_malloc(packetLength);

        if (!receiveAndVerifyKey(sock, mesgBuffer, packetLength, ephemeralPubKeyLen, hmaclen)) {
            fatal_error("HMAC verification");
        }

        EVP_PKEY *serverPubKey = setPublicKey(mesgBuffer + sizeof(uint16_t) + sizeof(uint16_t), ephemeralPubKeyLen);

        clientEntry->ack = *((uint16_t *)(mesgBuffer + sizeof(uint16_t)));

        sendSigningKey(*sock, signPubKey, pubKeyLen);
        sendEphemeralKey(*sock, clientEntry, ephemeralPubKey, ephemeralPubKeyLen, hmac, hmaclen);

        sharedSecret = getSharedSecret(ephemeralKey, serverPubKey);

        free(mesgBuffer);
        EVP_PKEY_free(serverPubKey);
    }
    clientEntry->sharedKey = sharedSecret;

    OPENSSL_free(signPubKey);
    OPENSSL_free(ephemeralPubKey);
    OPENSSL_free(hmac);
    EVP_PKEY_free(ephemeralKey);

    return sharedSecret;
}

bool receiveAndVerifyKey(const int * const sock, unsigned char *buffer, const size_t bufSize, const size_t keyLen, const size_t hmacLen) {
    assert(bufSize >= keyLen + hmacLen + sizeof(uint16_t) + sizeof(uint16_t));

    size_t n = singleEpollReadInstance(*sock, buffer, bufSize);
    assert(n >= keyLen);

    debug_print_buffer("Received ephemeral key: ", buffer, n);

    EVP_PKEY *serverPubKey = setPublicKey(buffer + (sizeof(uint16_t) * 2), keyLen);

    struct client *entry = container_entry(sock, struct client, socket);

    bool rtn = verifyHMAC_PKEY(buffer + (sizeof(uint16_t) * 2), keyLen, buffer + (sizeof(uint16_t) * 2) + keyLen, hmacLen, entry->signingKey);

    EVP_PKEY_free(serverPubKey);
    return rtn;
}

void startClient(const char *ip, const char *portString, int inputFD) {
    network_init();

    int serverSock;
    if (ip == NULL) {
        char *address = getUserInput("Enter the server's address: ");
        serverSock = establishConnection(address, portString);
        free(address);
    } else {
        serverSock = establishConnection(ip, portString);
    }

    if (serverSock == -1) {
        fprintf(stderr, "Unable to connect to server\n");
        goto clientCleanup;
    }

    setNonBlocking(serverSock);

    size_t clientNum = addClient(serverSock);

    struct client *serverEntry = &clientList[clientNum];

    unsigned char *sharedSecret = exchangeKeys(&serverEntry->socket);

    debug_print_buffer("Shared secret: ", sharedSecret, SYMMETRIC_KEY_SIZE);

    int epollfd = createEpollFd();

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.ptr = serverEntry;

    addEpollSocket(epollfd, serverSock, &ev);

    pthread_t readThread;
    pthread_create(&readThread, NULL, eventLoop, &epollfd);

    unsigned char buffer[MAX_USER_BUFFER];
    while(isRunning) {
        int n = read(inputFD, buffer, MAX_USER_BUFFER);
        if (n <= 0) {
            break;
        }
        printf("Read %d\n", n);
        sendReliablePacket((unsigned char *) buffer, n, serverEntry);
        ++serverEntry->seq;
    }

clientCleanup:
    close(epollfd);
    close(inputFD);
    network_cleanup();
}

void startServer(void) {
    network_init();

    int epollfd = createEpollFd();

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.ptr = NULL;

    setNonBlocking(listenSock);

    addEpollSocket(epollfd, listenSock, &ev);

    //TODO: Create threads here instead of calling eventloop directly
    eventLoop(&epollfd);

    network_cleanup();
}

void *eventLoop(void *epollfd) {
    int efd = *((int *)epollfd);

    struct epoll_event *eventList = checked_calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));

    while (isRunning) {
        int n = waitForEpollEvent(efd, eventList);
        //n can't be -1 because the handling for that is done in waitForEpollEvent
        for (int i = 0; i < n; ++i) {
            if (eventList[i].events & EPOLLERR || eventList[i].events & EPOLLHUP) {
                int sock = (eventList[i].data.ptr) ? ((struct client *) eventList[i].data.ptr)->socket : listenSock;
                handleSocketError(sock);
            } else if (eventList[i].events & EPOLLIN) {
                if (eventList[i].data.ptr) {
                    //Regular read connection
                    handleIncomingPacket(eventList[i].data.ptr);
                } else {
                    //Null data pointer means listen socket has incoming connection
                    handleIncomingConnection(efd);
                }
            }
        }
    }
    free(eventList);
    return NULL;
}

size_t addClient(int sock) {
    pthread_mutex_lock(&clientLock);
    bool foundEntry = false;
    for (size_t i = 0; i < clientCount; ++i) {
        if (clientList[i].enabled == false) {
            initClientStruct(clientList + i, sock);
            ++clientCount;
            foundEntry = true;
            break;
        }
    }
    if (!foundEntry) {
        clientList = checked_realloc(clientList, sizeof(struct client) * clientCount * 2);
        memset(clientList + clientCount, 0, sizeof(struct client) * clientCount);
        initClientStruct(clientList + clientCount, sock);
        ++clientCount;
    }
    pthread_mutex_unlock(&clientLock);
    //Subtract 2: 1 for incremented client count, 1 for dummy value
    return clientCount - 2;
}

void initClientStruct(struct client *newClient, int sock) {
    newClient->socket = sock;
    newClient->sharedKey = NULL;
    newClient->signingKey = NULL;
    newClient->enabled = true;

    //The following 3 values are dummies as the protocol handling is not implemented yet
    newClient->seq = 0xff;
    newClient->ack = 0xff;
    newClient->windowSize = 0xff;
}

void sendEncryptedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *dest, const bool isAck) {
    //Mesg is the plaintext, and does not include the sequence or ack, etc numbers
    assert(mesgLen <= MAX_USER_BUFFER);
    /*
     * Mesg buffer that will be sent
     * mesgLen is self-explanatory
     * BLOCK_SIZE since encryption can pad up to one block length
     * IV_SIZE is self-explanatory
     * HASH_SIZE is for the HMAC
     * sizeof calls are related to header specific lengths
     */
    unsigned char *out = checked_malloc(HEADER_SIZE + mesgLen + BLOCK_SIZE + IV_SIZE + HASH_SIZE);

    //Buffer to hold mesg plus mesg header, not including packet length
    unsigned char wrappedMesg[mesgLen + HEADER_SIZE - sizeof(uint16_t)];

    //Fill wrappedMesg with appropriate values
    memset(wrappedMesg, (isAck) ? ACK : NONE, sizeof(unsigned char));
    memcpy(wrappedMesg + sizeof(unsigned char), &dest->seq, sizeof(uint16_t));
    memcpy(wrappedMesg + sizeof(unsigned char) + sizeof(uint16_t), &dest->ack, sizeof(uint16_t));
    memcpy(wrappedMesg + sizeof(unsigned char) + (sizeof(uint16_t) * 2), &dest->windowSize, sizeof(uint16_t));
    memcpy(wrappedMesg + sizeof(unsigned char) + (sizeof(uint16_t) * 3), mesg, mesgLen);

    unsigned char iv[IV_SIZE];
    fillRandom(iv, IV_SIZE);

    //Encrypt message and place it immediately following length field
    size_t cipherLen = encrypt(wrappedMesg, mesgLen + HEADER_SIZE - sizeof(uint16_t), dest->sharedKey, iv, out + sizeof(uint16_t));

    assert(cipherLen <= mesgLen + HEADER_SIZE - sizeof(uint16_t) + BLOCK_SIZE);

    uint16_t packetLength = cipherLen + IV_SIZE + HASH_SIZE + sizeof(uint16_t);
    //Write packet length to start of packet buffer
    memcpy(out, &packetLength, sizeof(uint16_t));

    //Write the IV into the buffer
    memmove(out + sizeof(uint16_t) + cipherLen, iv, IV_SIZE);

    //Index of the hmac start in the packet buffer
    const size_t hmacIndex = sizeof(uint16_t) + cipherLen + IV_SIZE;

    size_t hmacLen = 0;
    //Generate HMAC over the ciphertext, packet length, and IV
    unsigned char *hmac = generateHMAC_Buffer(out, hmacIndex, &hmacLen, dest->sharedKey, SYMMETRIC_KEY_SIZE);

    assert(hmacLen <= EVP_MAX_MD_SIZE);
    assert(hmacLen == HASH_SIZE);

    debug_print_buffer("Sent hmac: ", hmac, HASH_SIZE);

    //Write the hmac into the packet buffer
    memmove(out + hmacIndex, hmac, hmacLen);
    OPENSSL_free(hmac);

    debug_print_buffer("Sending packets with contents: ", out, packetLength);

    //Write the packet to the socket
    rawSend(dest->socket, out, packetLength);

    free(out);
}

void decryptReceivedUserData(const unsigned char *mesg, const size_t mesgLen, struct client *src) {
    assert(mesgLen > IV_SIZE + HASH_SIZE);

    debug_print_buffer("Received hmac: ", mesg + mesgLen - HASH_SIZE, HASH_SIZE);

    bool validPacket = verifyHMAC_Buffer(mesg, mesgLen - HASH_SIZE, mesg + mesgLen - HASH_SIZE, HASH_SIZE, src->sharedKey, SYMMETRIC_KEY_SIZE);
    if (!validPacket) {
        fprintf(stderr, "Packet HMAC failed to verify, dropping...\n");
        return;
    }

    //Ack the validated packet
    if (isServer) {
        sendEncryptedUserData((const unsigned char *) "", 0, src, true);
        ++src->ack;
    }

    unsigned char *plain = checked_malloc(mesgLen);
    size_t plainLen = decrypt(mesg + sizeof(uint16_t), mesgLen - HASH_SIZE - IV_SIZE - sizeof(uint16_t), src->sharedKey, mesg + mesgLen - HASH_SIZE - IV_SIZE, plain);

    process_packet(plain, plainLen, src);

    free(plain);
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

void sendReliablePacket(const unsigned char *mesg, const size_t mesgLen, struct client *dest) {
    int retryCount = 0;
start:
    pthread_mutex_lock(&clientLock);
    ackReceived = false;
    pthread_mutex_unlock(&clientLock);

    sendEncryptedUserData(mesg, mesgLen, dest, false);

    pthread_mutex_lock(&clientLock);
    int n;
wait:

    clock_gettime(CLOCK_REALTIME, &timeToWait);
    timespec_add_ns(&timeToWait, TIMEOUT_NS);

    n = pthread_cond_timedwait(&cv, &clientLock, &timeToWait);
    if (n == 0) {
        if (ackReceived) {
            //Successful wakeup
            pthread_mutex_unlock(&clientLock);
            return;
        } else {
            //Spurious wakeup, wait again
            goto wait;
        }
    } else {
        if (n == ETIMEDOUT) {
            //Timeout occurred, resend packet
            pthread_mutex_unlock(&clientLock);
            ++retryCount;
            if (retryCount >= MAX_RETRIES) {
                fprintf(stderr, "Connection timed out\n");
                isRunning = false;
                return;
            }
            goto start;
        } else {
            errno = n;
            pthread_mutex_unlock(&clientLock);
            fatal_error("pthread_cond_wait");
        }
    }
    __builtin_unreachable();
}

void handleIncomingConnection(const int efd) {
    for(;;) {
        int sock = accept(listenSock, NULL, NULL);
        if (sock == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //No incoming connections, ignore the error
                break;
            }
            fatal_error("accept");
        }

        setNonBlocking(sock);

        size_t newClientIndex = addClient(sock);

        unsigned char *secretKey = exchangeKeys(&clientList[newClientIndex].socket);
        debug_print_buffer("Shared secret: ", secretKey, HASH_SIZE);

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        ev.data.ptr = &clientList[newClientIndex];

        addEpollSocket(efd, sock, &ev);
    }
}

void handleSocketError(const int sock) {
    fprintf(stderr, "Socket error on socket %d\n", sock);
    close(sock);
}

uint16_t readPacketLength(const int sock) {
    uint16_t sizeToRead = 0;

    int n = readNBytes(sock, (unsigned char *) &sizeToRead, sizeof(uint16_t));
    if (n == 0) {
        //Client has left us
        return 0;
    }
    assert(n == 2);

    assert(sizeToRead < MAX_PACKET_SIZE + sizeof(uint16_t));
    assert(sizeToRead != 0);

    return sizeToRead;
}

void handleIncomingPacket(struct client *src) {
    const int sock = src->socket;
    unsigned char *buffer = checked_malloc(MAX_PACKET_SIZE);
    for (;;) {
        //uint16_t sizeToRead = 0;
        uint16_t sizeToRead = readPacketLength(sock);
        if (sizeToRead == 0) {
            //Client has left us
            break;
        }
        memcpy(buffer, &sizeToRead, sizeof(uint16_t));
        printf("Packet size to read: %d\n", sizeToRead);
        {
            unsigned char *tmpBuf = buffer + sizeof(uint16_t);
            uint16_t tmpSize = sizeToRead - sizeof(uint16_t);

            int len;
            for (;;) {
                len = readNBytes(sock, tmpBuf, tmpSize);
                assert(len <= tmpSize);
                if (len == tmpSize) {
                    debug_print_buffer("Raw Received packet: ", buffer, sizeToRead);
                    decryptReceivedUserData(buffer, sizeToRead, src);
                    break;
                }
                //Len must be less than tmpSize
                if (len < tmpSize) {
                    tmpBuf += len;
                    tmpSize -= len;
                    continue;
                }
            }
        }
    }
    free(buffer);
}

void sendSigningKey(const int sock, const unsigned char *key, const size_t keyLen) {
    uint16_t packetLength = keyLen + sizeof(uint16_t);
    unsigned char tmpSigningKeyBuffer[packetLength];

    memcpy(tmpSigningKeyBuffer, &packetLength, sizeof(uint16_t));
    memcpy(tmpSigningKeyBuffer + sizeof(uint16_t), key, keyLen);

    debug_print_buffer("Sent signing key: ", tmpSigningKeyBuffer, packetLength);

    debug_print_buffer("Actual signing key: ", key, keyLen);
    rawSend(sock, tmpSigningKeyBuffer, packetLength);
}

void sendEphemeralKey(const int sock, struct client *clientEntry, const unsigned char *key, const size_t keyLen, const unsigned char *hmac, const size_t hmacLen) {
    uint16_t packetLength = keyLen + hmacLen + sizeof(uint16_t) + sizeof(uint16_t);

    //unsigned char *mesgBuffer = checked_malloc(packetLength);
    unsigned char mesgBuffer[packetLength];
    memcpy(mesgBuffer, &packetLength, sizeof(uint16_t));
    fillRandom((unsigned char *) &(clientEntry->seq), sizeof(uint16_t));
    memcpy(mesgBuffer + sizeof(uint16_t), &clientEntry->seq, sizeof(uint16_t));
    memcpy(mesgBuffer + sizeof(uint16_t) + sizeof(uint16_t), key, keyLen);
    memcpy(mesgBuffer + sizeof(uint16_t) + sizeof(uint16_t) + keyLen, hmac, hmacLen);

    debug_print_buffer("Sent ephemeral key: ", mesgBuffer, packetLength);

    rawSend(sock, mesgBuffer, packetLength);
}

void readSigningKey(const int sock, struct client *clientEntry, const size_t keyLen) {
    const uint16_t packetLength = keyLen + sizeof(uint16_t);
    unsigned char mesgBuffer[packetLength];
    size_t n = singleEpollReadInstance(sock, mesgBuffer, packetLength);

    debug_print_buffer("Received signing key: ", mesgBuffer, packetLength);

    clientEntry->signingKey = setPublicKey(mesgBuffer + sizeof(uint16_t), n - sizeof(uint16_t));
}
