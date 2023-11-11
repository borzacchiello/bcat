#ifndef RELDGRAM_H
#define RELDGRAM_H

#include <netinet/in.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "queue.h"
#include "ikcp.h"

#define NO_ERR                    0
#define ERR_WRONG_TYPE            -1
#define ERR_PTHREAD_CREATE_FAILED -2
#define ERR_PEER_OFFLINE          -3
#define ERR_TOO_MANY_RETRY        -4
#define ERR_BUFFER_TOO_LONG       -5

typedef struct connection_t {
    void* obj;
    int   (*sendto)(void* obj, struct sockaddr_in* addr, const uint8_t* data,
                  uint32_t data_size);
    int   (*recvfrom)(void* obj, struct sockaddr_in* addr, uint8_t* data,
                    uint32_t data_size, uint32_t timeout);

    pthread_mutex_t lock;
    int             shared_count;

    int    connected;
    time_t last_alive;

    ikcpcb*            ikcp;
    struct sockaddr_in peer;
} connection_t;

typedef struct reldgram_t {
    // FIXME: this lock is used for *everything* and is shared among all the
    //        peers of the server it is unnecessary, and should be improved.
    //        In this phase I prefer to keep the things simple
    pthread_mutex_t* lock;

    void* obj;
    int   (*sendto)(void* obj, struct sockaddr_in* addr, const uint8_t* data,
                  uint32_t data_size);
    int   (*recvfrom)(void* obj, struct sockaddr_in* addr, uint8_t* data,
                    uint32_t data_size, uint32_t timeout);
    int   max_pkt_size;

    int       type;
    int       disconnected;
    int       thread_running;
    pthread_t thread;

    queue_t*       pending;
    connection_t** conns;
    size_t         conns_capacity;
    size_t         conns_size;
} reldgram_t;

const char* reldgram_strerror(int errnum);

reldgram_t* reldgram_init(void* obj,
                          int   (*sendto)(void* obj, struct sockaddr_in* addr,
                                        const uint8_t* data,
                                        uint32_t       data_size),
                          int   (*recvfrom)(void* obj, struct sockaddr_in* addr,
                                          uint8_t* data, uint32_t data_size,
                                          uint32_t timeout));
void        reldgram_destroy(reldgram_t* rd);
void        reldgram_disconnect(reldgram_t* rd);

int         reldgram_listen(reldgram_t* rd);
reldgram_t* reldgram_accept(reldgram_t* rd);
int         reldgram_connect(reldgram_t* rd, struct sockaddr_in* addr);

int reldgram_send(reldgram_t* rd, const uint8_t* data, uint32_t data_size);
int reldgram_recv(reldgram_t* rd, uint8_t* data, uint32_t data_size,
                  uint32_t* nread);

int reldgram_get_peer_info(reldgram_t* rd, char** addr, int* port);

#endif
