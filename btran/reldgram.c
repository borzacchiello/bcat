#include <arpa/inet.h>
#include <sys/time.h>
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

#define MAX_CONN_RETRY        10
#define CONN_RETRY_SLEEP_TIME 100
#define RECV_POLL_TIMEOUT     10
#define ALIVE_SEC_THRESHOLD   10

#define PENDING_CONN_CAPACITY 10

#define PKT_CONN     ((uint8_t)0)
#define PKT_CONN_ACK ((uint8_t)1)
#define PKT_DATA     ((uint8_t)2)
#define PKT_RST      ((uint8_t)3)
#define PKT_PING     ((uint8_t)4)
#define PKT_PING_ACK ((uint8_t)5)

#define TY_UNINITIALIZED   0
#define TY_SERVER_LISTENER 1
#define TY_SERVER_PEER     2
#define TY_CLIENT_PEER     3

static const uint8_t pkt_conn[]     = {PKT_CONN};
static const uint8_t pkt_conn_ack[] = {PKT_CONN_ACK};
static const uint8_t pkt_rst[]      = {PKT_RST};
static const uint8_t pkt_ping[]     = {PKT_PING};
static const uint8_t pkt_ping_ack[] = {PKT_PING_ACK};

static int ikcp_out(const char* buf, int len, ikcpcb* kcp, void* user)
{
    (void)kcp;

    if (len < 0)
        panic("ikcp_out(): unexpected len (%d)", len);

    debug("ikcp_out(): sending data [len: %d]", len);
    connection_t* conn = (connection_t*)user;

    uint8_t* pkt = btran_malloc(len + 1);
    memcpy(pkt + 1, buf, len);
    pkt[0] = PKT_DATA;

    int r = conn->sendto(conn->obj, &conn->peer, (const uint8_t*)pkt,
                         (uint32_t)(len + 1));
    btran_free(pkt);
    return r;
}

static connection_t* mk_connection(struct sockaddr_in* peer, reldgram_t* rd)
{
    connection_t* conn = btran_malloc(sizeof(connection_t));
    conn->connected    = 1;
    conn->obj          = rd->obj;
    conn->sendto       = rd->sendto;
    conn->recvfrom     = rd->recvfrom;
    conn->peer         = *peer;
    conn->last_alive   = time(0);
    conn->ikcp         = ikcp_create(1337, conn);
    conn->shared_count = 0;
    ikcp_setmtu(conn->ikcp, rd->max_pkt_size);
    ikcp_setoutput(conn->ikcp, ikcp_out);
    pthread_mutex_init(&conn->lock, NULL);
    return conn;
}

static void del_connection(connection_t* conn)
{
    int must_delete = 0;
    RUN_OR_FAIL(pthread_mutex_lock(&conn->lock));
    conn->shared_count -= 1;
    must_delete = conn->shared_count <= 0;
    RUN_OR_FAIL(pthread_mutex_unlock(&conn->lock));

    if (must_delete) {
        pthread_mutex_destroy(&conn->lock);
        ikcp_release(conn->ikcp);
        btran_free(conn);
    }
}

static time_t time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
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
        case ERR_BUFFER_TOO_LONG:
            return "buffer too long";
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
    rd->max_pkt_size   = 1400;
    rd->disconnected   = 0;

    rd->lock = btran_malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(rd->lock, NULL);
    return rd;
}

void reldgram_disconnect(reldgram_t* rd)
{
    debug("reldgram_disconnect(): disconnecting peer");
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
    if (rd->disconnected) {
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        return;
    }

    for (size_t i = 0; i < rd->conns_size; ++i) {
        // send a RST packet to the peer
        if (rd->conns[i]->connected) {
            ikcp_flush(rd->conns[i]->ikcp);
            while (1) {
                int numpkt = ikcp_waitsnd(rd->conns[i]->ikcp);
                if (numpkt <= 0)
                    break;

                RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
                sleep(1);
                RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
            }
            rd->sendto(rd->obj, &rd->conns[i]->peer, pkt_rst, sizeof(pkt_rst));
            rd->conns[i]->connected = 0;
        }
    }

    rd->disconnected = 1;
    if (rd->type != TY_SERVER_PEER && rd->thread_running) {
        rd->thread_running = 0;
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        pthread_join(rd->thread, NULL);
    } else {
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    }
    debug("reldgram_disconnect(): done");
}

void reldgram_destroy(reldgram_t* rd)
{
    debug("reldgram_destroy(): releasing resources");
    reldgram_disconnect(rd);

    for (size_t i = 0; i < rd->conns_size; ++i)
        del_connection(rd->conns[i]);
    btran_free(rd->conns);

    if (rd->pending)
        queue_destroy(rd->pending, &free);

    rd->pending        = NULL;
    rd->conns          = NULL;
    rd->conns_size     = 0;
    rd->conns_capacity = 0;

    if (rd->type != TY_SERVER_PEER) {
        pthread_mutex_destroy(rd->lock);
        btran_free(rd->lock);
    }
    btran_free(rd);
}

static void* thread_listen(void* _rd)
{
    reldgram_t* rd = (reldgram_t*)_rd;

    uint8_t            tmp[rd->max_pkt_size + 1];
    struct sockaddr_in addr;

    while (1) {
        RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
        if (!rd->thread_running) {
            RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
            break;
        }
        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);

        time_t currtime = time_ms();
        for (size_t i = 0; i < rd->conns_size; ++i)
            if (rd->conns[i]->connected)
                ikcp_update(rd->conns[i]->ikcp, currtime);

        if (n <= 0) {
            // no data, in the meanwhile:
            //     - check if some peer disconnected
            //     - send PING if needed
            time_t curtime = time(0);
            for (size_t i = 0; i < rd->conns_size; ++i) {
                if (!rd->conns[i]->connected ||
                    curtime - rd->conns[i]->last_alive >=
                        3 * ALIVE_SEC_THRESHOLD) {
                    debug("thread_listen(): disconnecting (timeout)");
                    connection_t* conn = rd->conns[i];
                    conn->connected    = 0;
                    del_connection(conn);
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
            RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
            msleep(10);
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN: {
                // handle new connections
                if (n != 1)
                    // malformed packet
                    break;

                debug("thread_listen(): received CONN pkt");
                int has_conn = 0;
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
                    debug("thread_listen(): the peer already has an active "
                          "connection");
                    rd->sendto(rd->obj, &addr, pkt_conn_ack,
                               sizeof(pkt_conn_ack));
                    continue;
                }

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
                    debug("thread_listen(): the peer is already in pending "
                          "queue");
                    rd->sendto(rd->obj, &addr, pkt_conn_ack,
                               sizeof(pkt_conn_ack));
                    break;
                }

                struct sockaddr_in* paddr =
                    btran_malloc(sizeof(struct sockaddr_in));
                *paddr = addr;
                if (queue_write(rd->pending, paddr) != 0)
                    // not enough space in queue, dropping the connection
                    btran_free(paddr);
                debug("thread_listen(): peer added to pending queue");
                break;
            }
            case PKT_DATA: {
                // handle reception of a new packet
                if (n < 2)
                    // malformed packet
                    break;
                debug("thread_listen(): received DATA pkt");
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        debug("thread_listen(): data dispatched [len: %d]",
                              n - 1);
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        ikcp_input(conn->ikcp, (const char*)(tmp + 1), n - 1);
                        break;
                    }
                break;
            }
            case PKT_PING: {
                // handle ping packet
                if (n != 1)
                    // malformed packet
                    break;

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
                break;
            }
            case PKT_PING_ACK: {
                // handle ping ack packet
                if (n != 1)
                    // malformed packet
                    break;

                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        connection_t* conn = rd->conns[i];
                        conn->last_alive   = time(0);
                        break;
                    }
                break;
            }
            case PKT_RST: {
                // handle reset packet
                if (n != 1)
                    // malformed packet
                    break;

                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        debug("thread_listen(): received RST");
                        connection_t* conn = rd->conns[i];
                        conn->connected    = 0;
                        del_connection(conn);
                        if (i < rd->conns_size - 1)
                            rd->conns[i] = rd->conns[rd->conns_size - 1];
                        rd->conns_size -= 1;
                        break;
                    }
                break;
            }
            default:
                // unexpected packet
                break;
        }
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    }
    return NULL;
}

static void* thread_client_peer(void* _rd)
{
    reldgram_t* rd = (reldgram_t*)_rd;

    uint8_t            tmp[rd->max_pkt_size + 1];
    struct sockaddr_in addr;

    while (1) {
        RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
        if (!rd->thread_running) {
            RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
            break;
        }

        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);
        if (rd->conns[0]->connected) {
            time_t currtime = time_ms();
            ikcp_update(rd->conns[0]->ikcp, currtime);
        }
        if (n <= 0) {
            time_t curtime = time(0);
            if (curtime - rd->conns[0]->last_alive >= 3 * ALIVE_SEC_THRESHOLD) {
                // no data for too long, silently disconnect
                rd->conns[0]->connected = 0;
                rd->thread_running      = 0;
                break;
            } else if (curtime - rd->conns[0]->last_alive >=
                       ALIVE_SEC_THRESHOLD) {
                // no data for a while, let's ping the peer
                rd->sendto(rd->obj, &rd->conns[0]->peer, pkt_ping,
                           sizeof(pkt_ping));
            }
            RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
            msleep(10);
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN_ACK: {
                // conclude connection
                if (n != 1)
                    // malformed packet
                    break;

                debug("thread_client_peer(): received CONN_ACK pkt");
                connection_t* conn = rd->conns[0];
                if (!conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    debug("thread_client_peer(): connection was successfull");
                    conn->last_alive = time(0);
                    conn->connected  = 1;
                }
                break;
            }
            case PKT_DATA: {
                // handle reception of a new packet
                if (n < 2)
                    // malformed packet
                    break;

                debug("thread_client_peer(): received DATA pkt");
                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    debug("thread_client_peer(): data dispatched [len: %d]",
                          n - 1);
                    conn->last_alive = time(0);
                    ikcp_input(conn->ikcp, (const char*)(tmp + 1), n - 1);
                }
                break;
            }
            case PKT_PING: {
                // handle ping packet
                if (n != 1)
                    // malformed packet
                    break;

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
                    break;

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
                    break;

                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    conn->connected    = 0;
                    rd->thread_running = 0;
                }
                break;
            }
            default:
                // unexpected packet
                break;
        }
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    }
    return NULL;
}

int reldgram_listen(reldgram_t* rd)
{
    int r = NO_ERR;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));

    if (rd->type != TY_UNINITIALIZED) {
        r = ERR_WRONG_TYPE;
        goto cleanup;
    }

    rd->type           = TY_SERVER_LISTENER;
    rd->pending        = queue_init(PENDING_CONN_CAPACITY);
    rd->conns_capacity = 10;
    rd->conns_size     = 0;
    rd->conns = btran_malloc(sizeof(connection_t*) * rd->conns_capacity);
    rd->thread_running = 1;
    if (pthread_create(&rd->thread, NULL, &thread_listen, rd) != 0) {
        r = ERR_PTHREAD_CREATE_FAILED;
        goto cleanup;
    }

cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}

#define ACCEPT_OK    0
#define ACCEPT_RETRY 1
#define ACCEPT_ERR   2
static int accept_try_one(reldgram_t* rd, reldgram_t** out)
{
    int r = NO_ERR;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));

    if (rd->type != TY_SERVER_LISTENER) {
        r = ACCEPT_ERR;
        goto cleanup;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)queue_read(rd->pending);
    if (addr == NULL) {
        r = ACCEPT_RETRY;
        goto cleanup;
    }

    reldgram_t* res = reldgram_init(rd->obj, rd->sendto, rd->recvfrom);

    // lock is shared with main thread
    pthread_mutex_destroy(res->lock);
    btran_free(res->lock);
    res->lock = rd->lock;

    res->type = TY_SERVER_PEER;
    if (rd->conns_capacity == rd->conns_size) {
        rd->conns_capacity *= 2;
        rd->conns =
            realloc(rd->conns, rd->conns_capacity * sizeof(connection_t*));
    }
    rd->conns[rd->conns_size] = mk_connection(addr, rd);
    connection_t* conn        = rd->conns[rd->conns_size++];
    res->conns                = btran_malloc(sizeof(connection_t*));
    res->conns_size           = 1;
    res->conns_capacity       = 1;
    res->conns[0]             = conn;
    conn->shared_count        = 2;

    rd->sendto(rd->obj, addr, pkt_conn_ack, sizeof(pkt_conn_ack));
    btran_free(addr);

    *out = res;
cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}

reldgram_t* reldgram_accept(reldgram_t* rd)
{
    debug("reldgram_accept(): waiting for peer");

    reldgram_t* res = NULL;
    while (1) {
        int r = accept_try_one(rd, &res);
        if (r == ACCEPT_OK || r == ACCEPT_ERR)
            break;
        msleep(10);
    }

    debug("reldgram_accept(): returning from accept");
    return res;
}

int reldgram_connect(reldgram_t* rd, struct sockaddr_in* addr)
{
    debug("reldgram_connect(): trying to connect");

    int r = NO_ERR;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));

    if (rd->type != TY_UNINITIALIZED) {
        r = ERR_WRONG_TYPE;
        goto cleanup;
    }

    rd->type           = TY_CLIENT_PEER;
    rd->conns          = btran_malloc(sizeof(connection_t*));
    rd->conns_size     = 1;
    rd->conns_capacity = 1;
    rd->thread_running = 1;
    rd->conns[0]       = mk_connection(addr, rd);
    if (pthread_create(&rd->thread, NULL, &thread_client_peer, rd) != 0) {
        r = ERR_PTHREAD_CREATE_FAILED;
        goto cleanup;
    }
    debug("reldgram_connect(): thread created");

    rd->conns[0]->shared_count = 1;
    rd->conns[0]->connected    = 0;
    for (int i = 0; i < MAX_CONN_RETRY; ++i) {
        rd->sendto(rd->obj, addr, pkt_conn, sizeof(pkt_conn));

        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        msleep(CONN_RETRY_SLEEP_TIME);
        RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
        if (rd->conns[0]->connected)
            break;
    }
    if (!rd->conns[0]->connected) {
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        reldgram_disconnect(rd);
        del_connection(rd->conns[0]);
        rd->conns_size = 0;
        r              = ERR_PEER_OFFLINE;
    }
    debug("reldgram_connect(): connected");

cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}

int reldgram_send(reldgram_t* rd, const uint8_t* data, uint32_t data_size)
{
    debug("reldgram_send(): sending data");

    int r = NO_ERR;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
    if (rd->disconnected) {
        r = ERR_PEER_OFFLINE;
        goto cleanup;
    }
    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER) {
        r = ERR_WRONG_TYPE;
        goto cleanup;
    }
    if ((int)data_size < 0) {
        r = ERR_BUFFER_TOO_LONG;
        goto cleanup;
    }

    connection_t* conn = rd->conns[0];
    if (!conn->connected) {
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        reldgram_disconnect(rd);
        return ERR_PEER_OFFLINE;
    }

    ikcp_send(conn->ikcp, (const char*)data, (int)data_size);
    debug("reldgram_send(): data sent");

cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}

#define RECV_OK    0
#define RECV_RETRY 1
#define RECV_ERR   2
static int recv_try_one(reldgram_t* rd, uint8_t* data, uint32_t data_size,
                        uint32_t* nread, int* status)
{
    int r = RECV_OK;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
    if (rd->disconnected) {
        *status = ERR_PEER_OFFLINE;
        r       = RECV_ERR;
        goto cleanup;
    }
    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER) {
        *status = ERR_WRONG_TYPE;
        r       = RECV_ERR;
        goto cleanup;
    }
    if ((int)data_size < 0) {
        *status = ERR_BUFFER_TOO_LONG;
        r       = RECV_ERR;
        goto cleanup;
    }

    connection_t* conn = rd->conns[0];
    if (!conn->connected) {
        *status = ERR_PEER_OFFLINE;
        RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
        reldgram_disconnect(rd);
        return RECV_ERR;
    }
    int nr = ikcp_recv(conn->ikcp, (char*)data, (int)data_size);
    if (nr < 0) {
        r = RECV_RETRY;
        goto cleanup;
    }
    *nread = (uint32_t)nr;

cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}

int reldgram_recv(reldgram_t* rd, uint8_t* data, uint32_t data_size,
                  uint32_t* nread)
{
    debug("reldgram_recv(): waiting for data");
    while (1) {
        int status;
        int r = recv_try_one(rd, data, data_size, nread, &status);
        if (r == RECV_ERR)
            return status;
        if (r == RECV_OK)
            break;
        msleep(10);
    }

    debug("reldgram_recv(): data received [len: %u]", *nread);
    return NO_ERR;
}

int reldgram_get_peer_info(reldgram_t* rd, char** addr, int* port)
{
    int r = NO_ERR;
    RUN_OR_FAIL(pthread_mutex_lock(rd->lock));
    if (rd->type != TY_SERVER_PEER && rd->type != TY_CLIENT_PEER) {
        r = ERR_WRONG_TYPE;
        goto cleanup;
    }

    char buf[128] = {0};

    connection_t* conn = rd->conns[0];
    inet_ntop(AF_INET, &conn->peer.sin_addr, buf, INET_ADDRSTRLEN);
    *addr = btran_calloc(strlen(buf) + 1);
    *port = ntohs(conn->peer.sin_port);
    strcpy(*addr, buf);

cleanup:
    RUN_OR_FAIL(pthread_mutex_unlock(rd->lock));
    return r;
}
