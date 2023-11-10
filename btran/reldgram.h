#ifndef RELDGRAM_H
#define RELDGRAM_H

#include <netinet/in.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "queue.h"

#define NO_ERR                    0
#define ERR_WRONG_TYPE            -1
#define ERR_PTHREAD_CREATE_FAILED -2
#define ERR_PEER_OFFLINE          -3
#define ERR_TOO_MANY_RETRY        -4

typedef struct connection_t {
    atomic_bool connected;
    time_t      last_alive;

    pthread_mutex_t conn_lock;
    int             n_owners;

    atomic_uint_fast32_t recv_id;
    atomic_uint_fast32_t send_id;
    struct sockaddr_in   peer;
    queue_t*             msg_queue;
} connection_t;

typedef struct reldgram_t {
    void* obj;
    int   (*sendto)(void* obj, struct sockaddr_in* addr, const uint8_t* data,
                  uint32_t data_size);
    int   (*recvfrom)(void* obj, struct sockaddr_in* addr, uint8_t* data,
                    uint32_t data_size, uint32_t timeout);

    int         type;
    atomic_bool thread_running;
    pthread_t   thread;

    queue_t*        pending;
    pthread_mutex_t pending_lock;

    connection_t**  conns;
    size_t          conns_capacity;
    size_t          conns_size;
    pthread_mutex_t conns_lock;

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
int reldgram_recv(reldgram_t* rd, uint8_t** data, uint32_t* data_size);

int reldgram_get_peer_info(reldgram_t* rd, char** addr, int* port);

#endif
