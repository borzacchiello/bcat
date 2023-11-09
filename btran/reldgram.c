#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "reldgram.h"
#include "alloc.h"
#include "log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define RUN_OR_FAIL(runnable)                                                  \
    if (runnable != 0)                                                         \
        abort();

#define VERBOSE_SEND 0

#define RELDGRAM_MAX_PKT_SIZE 400
#define CONCURRENT_SEND       32

#define MAX_CONN_RETRY        10
#define SEND_RETRY_SLEEP_TIME 100
#define MAX_SEND_RETRY        16
#define CONN_RETRY_SLEEP_TIME 100
#define RECV_POLL_TIMEOUT     1
#define CONN_TIMEOUT          2
#define ALIVE_SEC_THRESHOLD   10

#define PENDING_CONN_CAPACITY 10
#define MSG_QUEUE_CAPACITY    256

#define PKT_CONN     ((uint8_t)0)
#define PKT_CONN_ACK ((uint8_t)1)
#define PKT_DATA     ((uint8_t)2)
#define PKT_DATA_ACK ((uint8_t)3)
#define PKT_RST      ((uint8_t)4)
#define PKT_PING     ((uint8_t)5)
#define PKT_PING_ACK ((uint8_t)6)

#define TY_UNINITIALIZED   0
#define TY_SERVER_LISTENER 1
#define TY_SERVER_PEER     2
#define TY_CLIENT_PEER     3

static const uint8_t pkt_conn[]     = {PKT_CONN};
static const uint8_t pkt_conn_ack[] = {PKT_CONN_ACK};
static const uint8_t pkt_rst[]      = {PKT_RST};
static const uint8_t pkt_ping[]     = {PKT_PING};
static const uint8_t pkt_ping_ack[] = {PKT_PING_ACK};

static void mk_pkt_data_ack(uint32_t id, uint8_t pkt[5])
{
    pkt[0]                = PKT_DATA_ACK;
    uint32_t id_netendian = htonl(id);
    memcpy(pkt + 1, (uint8_t*)&id_netendian, sizeof(uint32_t));
}

static void mk_pkt_data(uint32_t id, const uint8_t* data, uint32_t data_size,
                        uint8_t pkt[RELDGRAM_MAX_PKT_SIZE + 5])
{
    if (data_size > RELDGRAM_MAX_PKT_SIZE)
        abort();

    pkt[0]                = PKT_DATA;
    uint32_t id_netendian = htonl(id);
    memcpy(pkt + 1, (uint8_t*)&id_netendian, sizeof(uint32_t));
    memcpy(pkt + 5, data, data_size);
}

typedef struct msg_t {
    uint8_t* data;
    uint32_t size;
} msg_t;

static msg_t* mk_msg(uint8_t* data, uint32_t size)
{
    msg_t* msg = btran_malloc(sizeof(msg_t));
    msg->data  = btran_malloc(size);
    msg->size  = size;
    memcpy(msg->data, data, size);
    return msg;
}

static void del_msg(msg_t* msg)
{
    btran_free(msg->data);
    btran_free(msg);
}

static connection_t* mk_connection(struct sockaddr_in* peer, size_t queue_size)
{
    connection_t* conn = btran_malloc(sizeof(connection_t));
    conn->connected    = 1;
    conn->n_owners     = 0;
    conn->peer         = *peer;
    conn->msg_queue    = queue_init(queue_size);
    conn->last_alive   = time(0);
    conn->recv_id = conn->send_id = 0;
    pthread_mutex_init(&conn->conn_lock, NULL);
    return conn;
}

static void del_connection(connection_t* conn)
{
    queue_destroy(conn->msg_queue, (void (*)(void*)) & del_msg);
    pthread_mutex_destroy(&conn->conn_lock);
    btran_free(conn);
}

static void msleep(int msec) { usleep(msec * 1000); }

const char* reldgram_strerror(int errno)
{
    switch (errno) {
        case ERR_WRONG_TYPE:
            return "wrong type";
        case ERR_PTHREAD_CREATE_FAILED:
            return "pthread_create failed";
        case ERR_PEER_OFFLINE:
            return "peer offline";
        case ERR_TOO_MANY_RETRY:
            return "too many retry";
        default:
            break;
    }
    return "unknown";
}

reldgram_t* reldgram_init(void* obj,
                          int   (*sendto)(void* obj, struct sockaddr_in* addr,
                                        const uint8_t* data,
                                        uint32_t       data_size),
                          int   (*recvfrom)(void* obj, struct sockaddr_in* addr,
                                          uint8_t* data, uint32_t data_size,
                                          uint32_t timeout))
{
    reldgram_t* rd     = btran_malloc(sizeof(reldgram_t));
    rd->obj            = obj;
    rd->recvfrom       = recvfrom;
    rd->sendto         = sendto;
    rd->type           = TY_UNINITIALIZED;
    rd->thread_running = 0;
    rd->pending        = NULL;
    rd->conns          = NULL;
    rd->conns_size     = 0;
    rd->conns_capacity = 0;

    pthread_mutex_init(&rd->conns_lock, NULL);
    pthread_mutex_init(&rd->pending_lock, NULL);
    return rd;
}

void reldgram_disconnect(reldgram_t* rd)
{
    if (rd->thread_running) {
        rd->thread_running = 0;
        pthread_join(rd->thread, NULL);
    }

    for (size_t i = 0; i < rd->conns_size; ++i) {
        // send a RST packet to the peer
        rd->sendto(rd->obj, &rd->conns[i]->peer, pkt_rst, sizeof(pkt_rst));
        if (rd->type != TY_SERVER_PEER)
            del_connection(rd->conns[i]);
        else {
            // the connection of a server peer is shared with the listen thread,
            // we need to check whether the thread is using it
            RUN_OR_FAIL(pthread_mutex_lock(&rd->conns[i]->conn_lock));
            rd->conns[i]->connected = 0;
            rd->conns[i]->n_owners -= 1;
            if (rd->conns[i]->n_owners == 0) {
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns[i]->conn_lock));
                del_connection(rd->conns[i]);
            } else
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns[i]->conn_lock));
        }
    }
    btran_free(rd->conns);

    if (rd->pending)
        queue_destroy(rd->pending, &free);

    rd->type           = TY_UNINITIALIZED;
    rd->pending        = NULL;
    rd->conns          = NULL;
    rd->conns_size     = 0;
    rd->conns_capacity = 0;
}

void reldgram_destroy(reldgram_t* rd)
{
    reldgram_disconnect(rd);

    pthread_mutex_destroy(&rd->conns_lock);
    pthread_mutex_destroy(&rd->pending_lock);
    btran_free(rd);
}

static void* thread_listen(void* _rd)
{
    reldgram_t* rd = (reldgram_t*)_rd;

    uint8_t            tmp[RELDGRAM_MAX_PKT_SIZE + 5];
    struct sockaddr_in addr;

    while (rd->thread_running) {
        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);
        if (n <= 0) {
            // no data, in the meanwhile:
            //     - check if some peer disconnected
            //     - send PING if needed
            RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
            time_t curtime = time(0);
            for (size_t i = 0; i < rd->conns_size; ++i) {
                if (!rd->conns[i]->connected ||
                    curtime - rd->conns[i]->last_alive >=
                        3 * ALIVE_SEC_THRESHOLD) {
                    connection_t* conn = rd->conns[i];
                    RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                    conn->connected = 0;
                    conn->n_owners -= 1;
                    if (conn->n_owners == 0) {
                        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
                        del_connection(conn);
                    } else
                        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
                    if (i < rd->conns_size - 1)
                        rd->conns[i] = rd->conns[rd->conns_size - 1];
                    rd->conns_size -= 1;
                    break;
                } else if (curtime - rd->conns[i]->last_alive >=
                           ALIVE_SEC_THRESHOLD) {
                    // no data for a while, let's ping the peer
                    rd->sendto(rd->obj, &rd->conns[i]->peer, pkt_ping,
                               sizeof(pkt_ping));
                }
            }
            RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN: {
                // handle new connections
                if (n != 1)
                    // malformed packet
                    continue;

                RUN_OR_FAIL(pthread_mutex_lock(&rd->pending_lock));

                int has_conn = 0;
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        rd->conns[i]->last_alive = time(0);
                        has_conn                 = 1;
                        break;
                    }
                if (has_conn) {
                    // received a CONN packet in an established connection,
                    // resending CONN_ACK
                    RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                    RUN_OR_FAIL(pthread_mutex_unlock(&rd->pending_lock));
                    rd->sendto(rd->obj, &addr, pkt_conn_ack,
                               sizeof(pkt_conn_ack));
                    continue;
                }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));

                // check if in "pending" queue, and if not add it
                int    in_queue = 0;
                size_t i        = rd->pending->tail;
                while (i != rd->pending->head) {
                    struct sockaddr_in* paddr =
                        (struct sockaddr_in*)rd->pending->data[i];
                    if (paddr->sin_addr.s_addr == addr.sin_addr.s_addr &&
                        paddr->sin_port == addr.sin_port) {
                        in_queue = 1;
                        break;
                    }
                    i = (i + 1) % rd->pending->size;
                }
                if (in_queue) {
                    // the connection is already in queue, resending CONN_ACK
                    RUN_OR_FAIL(pthread_mutex_unlock(&rd->pending_lock));
                    rd->sendto(rd->obj, &addr, pkt_conn_ack,
                               sizeof(pkt_conn_ack));
                    continue;
                }

                struct sockaddr_in* paddr =
                    btran_malloc(sizeof(struct sockaddr_in));
                *paddr = addr;
                if (queue_write(rd->pending, paddr) != 0)
                    // not enough space in queue, dropping the connection
                    btran_free(paddr);
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->pending_lock));
                break;
            }
            case PKT_DATA: {
                // handle reception of a new packet
                if (n < 5)
                    // malformed packet
                    continue;
                uint32_t pkt_id_netendian;
                memcpy((uint8_t*)&pkt_id_netendian, tmp + 1, sizeof(uint32_t));
                uint32_t pkt_id = ntohl(pkt_id_netendian);

                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        if (pkt_id < conn->recv_id) {
                            // received the an old packet, sending ACK
                            uint8_t pkt[5];
                            mk_pkt_data_ack(pkt_id, pkt);
                            rd->sendto(rd->obj, &addr, pkt, sizeof(pkt));
                        } else if (conn->recv_id == pkt_id) {
                            // received the expected packet, adding to queue and
                            // sending ACK (if enqueue was successful)
                            msg_t* msg = mk_msg(tmp + 5, n - 5);
                            RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                            if (queue_write(conn->msg_queue, msg) == 0) {
                                conn->recv_id += 1;

                                uint8_t pkt[5];
                                mk_pkt_data_ack(pkt_id, pkt);
                                rd->sendto(rd->obj, &addr, pkt, sizeof(pkt));
                            } else
                                // queue is full
                                del_msg(msg);
                            RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
                        }
                        break;
                    }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                break;
            }
            case PKT_DATA_ACK: {
                // handle reception of an ack
                if (n != 5)
                    // malformed packet
                    continue;

                uint32_t pkt_id_netendian;
                memcpy((uint8_t*)&pkt_id_netendian, tmp + 1, sizeof(uint32_t));
                uint32_t pkt_id = ntohl(pkt_id_netendian);
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        if (conn->send_id == pkt_id)
                            conn->send_id += 1;
                        break;
                    }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                break;
            }
            case PKT_PING: {
                // handle ping packet
                if (n != 1)
                    // malformed packet
                    continue;
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        rd->sendto(rd->obj, &rd->conns[i]->peer, pkt_ping_ack,
                                   sizeof(pkt_ping_ack));
                        break;
                    }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                break;
            }
            case PKT_PING_ACK: {
                // handle ping ack packet
                if (n != 1)
                    // malformed packet
                    continue;
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        break;
                    }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                break;
            }
            case PKT_RST: {
                // handle reset packet
                if (n != 1)
                    // malformed packet
                    continue;

                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];

                        RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                        conn->connected = 0;
                        conn->n_owners -= 1;
                        if (conn->n_owners == 0) {
                            RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
                            del_connection(conn);
                        } else
                            RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));

                        if (i < rd->conns_size - 1)
                            rd->conns[i] = rd->conns[rd->conns_size - 1];
                        rd->conns_size -= 1;
                        break;
                    }
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
                break;
            }
            default:
                // unexpected packet
                break;
        }
    }
    return NULL;
}

static void* thread_client_peer(void* _rd)
{
    reldgram_t* rd = (reldgram_t*)_rd;

    uint8_t            tmp[RELDGRAM_MAX_PKT_SIZE + 5];
    struct sockaddr_in addr;

    while (rd->thread_running) {
        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);
        if (n <= 0) {
            time_t curtime = time(0);
            if (curtime - rd->conns[0]->last_alive >= 3 * ALIVE_SEC_THRESHOLD) {
                // no data for too long, silently disconnect
                rd->conns[0]->connected = 0;
            } else if (curtime - rd->conns[0]->last_alive >=
                       ALIVE_SEC_THRESHOLD) {
                // no data for a while, let's ping the peer
                rd->sendto(rd->obj, &rd->conns[0]->peer, pkt_ping,
                           sizeof(pkt_ping));
            }
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN_ACK: {
                // conclude connection
                if (n != 1)
                    // malformed packet
                    continue;

                connection_t* conn = rd->conns[0];
                if (conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->last_alive = time(0);
                    conn->connected  = 1;
                }
                break;
            }
            case PKT_DATA: {
                // handle reception of a new packet
                if (n < 5)
                    // malformed packet
                    continue;

                uint32_t pkt_id_netendian;
                memcpy((uint8_t*)&pkt_id_netendian, tmp + 1, sizeof(uint32_t));
                uint32_t      pkt_id = ntohl(pkt_id_netendian);
                connection_t* conn   = rd->conns[0];

                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->last_alive = time(0);
                    if (pkt_id < conn->recv_id) {
                        // received the an old packet, sending ACK
                        uint8_t pkt[5];
                        mk_pkt_data_ack(pkt_id, pkt);
                        rd->sendto(rd->obj, &addr, pkt, sizeof(pkt));
                    } else if (conn->recv_id == pkt_id) {
                        // received the expected packet, adding to queue and
                        // sending ACK (if enqueue was successful)
                        msg_t* msg = mk_msg(tmp + 5, n - 5);
                        RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                        if (queue_write(conn->msg_queue, msg) == 0) {
                            conn->recv_id += 1;

                            uint8_t pkt[5];
                            mk_pkt_data_ack(pkt_id, pkt);
                            rd->sendto(rd->obj, &addr, pkt, sizeof(pkt));
                        } else {
                            // queue is full
                            del_msg(msg);
                        }
                        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
                    }
                }
                break;
            }
            case PKT_DATA_ACK: {
                // handle reception of an ack
                if (n != 5)
                    // malformed packet
                    continue;

                connection_t* conn = rd->conns[0];
                uint32_t      pkt_id_netendian;
                memcpy((uint8_t*)&pkt_id_netendian, tmp + 1, sizeof(uint32_t));
                uint32_t pkt_id = ntohl(pkt_id_netendian);

                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->last_alive = time(0);
                    if (conn->send_id == pkt_id)
                        conn->send_id += 1;
                }
                break;
            }
            case PKT_PING: {
                // handle ping packet
                if (n != 1)
                    // malformed packet
                    continue;
                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {

                    conn->last_alive = time(0);
                    rd->sendto(rd->obj, &conn->peer, pkt_ping_ack,
                               sizeof(pkt_ping_ack));
                }
                break;
            }
            case PKT_PING_ACK: {
                // handle ping ack packet
                if (n != 1)
                    // malformed packet
                    continue;
                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->last_alive = time(0);
                }
                break;
            }
            case PKT_RST: {
                // handle reset packet
                if (n != 1)
                    // malformed packet
                    continue;

                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->connected = 0;
                }
                break;
            }
            default:
                // unexpected packet
                break;
        }
    }
    return NULL;
}

int reldgram_listen(reldgram_t* rd)
{
    if (rd->type != TY_UNINITIALIZED)
        return ERR_WRONG_TYPE;

    rd->type           = TY_SERVER_LISTENER;
    rd->pending        = queue_init(PENDING_CONN_CAPACITY);
    rd->conns_capacity = 10;
    rd->conns_size     = 0;
    rd->conns = btran_malloc(sizeof(connection_t*) * rd->conns_capacity);
    rd->thread_running = 1;
    if (pthread_create(&rd->thread, NULL, &thread_listen, rd) != 0)
        return ERR_PTHREAD_CREATE_FAILED;
    return NO_ERR;
}

reldgram_t* reldgram_accept(reldgram_t* rd)
{
    if (rd->type != TY_SERVER_LISTENER)
        return NULL;

    struct sockaddr_in* addr = NULL;
    while (addr == NULL) {
        RUN_OR_FAIL(pthread_mutex_lock(&rd->pending_lock));
        addr = (struct sockaddr_in*)queue_read(rd->pending);
        RUN_OR_FAIL(pthread_mutex_unlock(&rd->pending_lock));

        if (addr == NULL)
            msleep(100);
    }

    // a new connection, allocate data for it
    reldgram_t* res = reldgram_init(rd->obj, rd->sendto, rd->recvfrom);

    res->type = TY_SERVER_PEER;
    RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
    if (rd->conns_capacity == rd->conns_size) {
        rd->conns_capacity *= 2;
        rd->conns =
            realloc(rd->conns, rd->conns_capacity * sizeof(connection_t*));
    }
    rd->conns[rd->conns_size] = mk_connection(addr, MSG_QUEUE_CAPACITY);
    connection_t* conn        = rd->conns[rd->conns_size++];
    conn->n_owners            = 2;
    RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));

    res->conns          = btran_malloc(sizeof(connection_t*));
    res->conns_size     = 1;
    res->conns_capacity = 1;
    res->conns[0]       = conn;

    rd->sendto(rd->obj, addr, pkt_conn_ack, sizeof(pkt_conn_ack));
    btran_free(addr);
    return res;
}

int reldgram_connect(reldgram_t* rd, struct sockaddr_in* addr)
{
    if (rd->type != TY_UNINITIALIZED)
        return ERR_WRONG_TYPE;

    rd->type           = TY_CLIENT_PEER;
    rd->conns          = btran_malloc(sizeof(connection_t*));
    rd->conns_size     = 1;
    rd->conns_capacity = 1;
    rd->thread_running = 1;
    rd->conns[0]       = mk_connection(addr, MSG_QUEUE_CAPACITY);
    if (pthread_create(&rd->thread, NULL, &thread_client_peer, rd) != 0)
        return ERR_PTHREAD_CREATE_FAILED;

    rd->conns[0]->connected = 0;
    rd->conns[0]->n_owners  = 1;
    for (int i = 0; i < MAX_CONN_RETRY; ++i) {
        rd->sendto(rd->obj, addr, pkt_conn, sizeof(pkt_conn));
        msleep(CONN_RETRY_SLEEP_TIME);
        if (rd->conns[0]->connected)
            break;
    }
    if (!rd->conns[0]->connected) {
        reldgram_disconnect(rd);
        return ERR_PEER_OFFLINE;
    }
    return NO_ERR;
}

int reldgram_send(reldgram_t* rd, const uint8_t* data, uint32_t data_size)
{
    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER)
        return ERR_WRONG_TYPE;

    connection_t* conn      = rd->conns[0];
    time_t        init_time = time(0);
    int           time_tick = 0;

    uint32_t nsent = 0;
    while (nsent != data_size) {
        if (time_tick++ % 10 == 5 && VERBOSE_SEND) {
            time_t curr_time = time(0);
            printf("[+] sending %d / %d [%0.1Lf KB/s]\n", nsent, data_size,
                   (double)nsent / (double)(curr_time - init_time) / 1000.0l);
        }

        uint32_t pkt_id      = conn->send_id;
        uint32_t prev_pkt_id = pkt_id;
        int      num_retry   = MAX_SEND_RETRY;
        int      success     = 0;
        while (num_retry--) {
            if (!conn->connected) {
                if (rd->type == TY_CLIENT_PEER)
                    reldgram_disconnect(rd);
                return ERR_PEER_OFFLINE;
            }

            int      nchunk_sent = conn->send_id - pkt_id;
            uint32_t off         = nchunk_sent * RELDGRAM_MAX_PKT_SIZE;
            for (int i = nchunk_sent;
                 i < CONCURRENT_SEND && off + nsent < data_size; ++i) {
                uint32_t chunk_size =
                    min(RELDGRAM_MAX_PKT_SIZE, data_size - nsent - off);

                uint8_t pkt[RELDGRAM_MAX_PKT_SIZE + 5];
                mk_pkt_data(pkt_id + i, data + off + nsent, chunk_size, pkt);
                rd->sendto(rd->obj, &conn->peer, pkt, chunk_size + 5);

                off += chunk_size;
                nchunk_sent += 1;
                if (off == data_size) {
                    success = 0;
                    break;
                }
            }

            msleep(SEND_RETRY_SLEEP_TIME);
            if (conn->send_id == pkt_id + nchunk_sent) {
                nsent += off;
                success = 1;
                break;
            }
            if (conn->send_id != prev_pkt_id) {
                prev_pkt_id = conn->send_id;
                num_retry   = MAX_SEND_RETRY;
            }
        }
        if (!success)
            return ERR_TOO_MANY_RETRY;
    }
    return NO_ERR;
}

int reldgram_recv(reldgram_t* rd, uint8_t** data, uint32_t* data_size)
{
    *data      = NULL;
    *data_size = 0;

    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER)
        return ERR_WRONG_TYPE;

    connection_t* conn = rd->conns[0];
    while (1) {
        if (!conn->connected) {
            if (rd->type == TY_CLIENT_PEER)
                reldgram_disconnect(rd);
            return ERR_PEER_OFFLINE;
        }
        RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
        msg_t* msg;
        if ((msg = (msg_t*)queue_read(conn->msg_queue)) != NULL) {
            *data      = msg->data;
            *data_size = msg->size;
            btran_free(msg);
        }
        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
        if (*data)
            break;
        msleep(10);
    }
    return NO_ERR;
}

int reldgram_get_peer_info(reldgram_t* rd, char** addr, int* port)
{
    if (rd->type != TY_SERVER_PEER && rd->type != TY_CLIENT_PEER)
        return ERR_WRONG_TYPE;

    char buf[128] = {0};

    connection_t* conn = rd->conns[0];
    inet_ntop(AF_INET, &conn->peer.sin_addr, buf, INET_ADDRSTRLEN);
    *addr = btran_calloc(strlen(buf) + 1);
    *port = ntohs(conn->peer.sin_port);
    strcpy(*addr, buf);
    return NO_ERR;
}
