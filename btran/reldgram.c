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
#define TY_DISCONNECTED    4

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
    pthread_mutex_init(&conn->conn_lock, NULL);
    conn->connected  = 1;
    conn->n_owners   = 0;
    conn->obj        = rd->obj;
    conn->sendto     = rd->sendto;
    conn->recvfrom   = rd->recvfrom;
    conn->peer       = *peer;
    conn->last_alive = time(0);
    conn->ikcp       = ikcp_create(1337, conn);
    ikcp_setmtu(conn->ikcp, rd->max_pkt_size);
    ikcp_setoutput(conn->ikcp, ikcp_out);
    return conn;
}

static void del_connection(connection_t* conn)
{
    // connection is a shared pointer between the recv thread and the user
    // we need to check the if there are other owners before actually deleting
    RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
    conn->connected = 0;
    conn->n_owners -= 1;
    if (conn->n_owners < 0)
        panic("del_connection(): n_owners < 0");
    if (conn->n_owners == 0) {
        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
        ikcp_release(conn->ikcp);
        pthread_mutex_destroy(&conn->conn_lock);
        btran_free(conn);
    } else
        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
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

    pthread_mutex_init(&rd->conns_lock, NULL);
    pthread_mutex_init(&rd->pending_lock, NULL);
    return rd;
}

void reldgram_disconnect(reldgram_t* rd)
{
    RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
    for (size_t i = 0; i < rd->conns_size; ++i) {
        // send a RST packet to the peer
        if (rd->conns[i]->connected) {
            RUN_OR_FAIL(pthread_mutex_lock(&rd->conns[i]->conn_lock));
            ikcp_flush(rd->conns[i]->ikcp);
            while (1) {
                int numpkt = ikcp_waitsnd(rd->conns[i]->ikcp);
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns[i]->conn_lock));
                if (numpkt <= 0)
                    break;
                msleep(10);
            }
            rd->sendto(rd->obj, &rd->conns[i]->peer, pkt_rst, sizeof(pkt_rst));
            rd->conns[i]->connected = 0;
        }
    }
    RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));

    if (rd->thread_running) {
        rd->thread_running = 0;
        pthread_join(rd->thread, NULL);
    }
    rd->type = TY_DISCONNECTED;
}

void reldgram_destroy(reldgram_t* rd)
{
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

    pthread_mutex_destroy(&rd->conns_lock);
    pthread_mutex_destroy(&rd->pending_lock);
    btran_free(rd);
}

static void* thread_listen(void* _rd)
{
    reldgram_t* rd = (reldgram_t*)_rd;

    uint8_t            tmp[rd->max_pkt_size + 1];
    struct sockaddr_in addr;

    while (rd->thread_running) {
        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);

        RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
        time_t currtime = time_ms();
        for (size_t i = 0; i < rd->conns_size; ++i)
            if (rd->conns[i]->connected) {
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns[i]->conn_lock));
                ikcp_update(rd->conns[i]->ikcp, currtime);
                RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns[i]->conn_lock));
            }
        RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));

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
            RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns_lock));
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN: {
                // handle new connections
                if (n != 1)
                    // malformed packet
                    continue;

                debug("thread_listen(): received CONN pkt");
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
                    debug("thread_listen(): the peer already has an active "
                          "connection");
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
                    debug("thread_listen(): the peer is already in pending "
                          "queue");
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
                debug("thread_listen(): peer added to pending queue");
                break;
            }
            case PKT_DATA: {
                // handle reception of a new packet
                if (n < 2)
                    // malformed packet
                    continue;
                debug("thread_listen(): received DATA pkt");
                RUN_OR_FAIL(pthread_mutex_lock(&rd->conns_lock));
                for (size_t i = 0; i < rd->conns_size; ++i)
                    if (rd->conns[i]->connected &&
                        rd->conns[i]->peer.sin_addr.s_addr ==
                            addr.sin_addr.s_addr &&
                        rd->conns[i]->peer.sin_port == addr.sin_port) {
                        debug("thread_listen(): data dispatched [len: %d]",
                              n - 1);
                        connection_t* conn = rd->conns[i];
                        RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                        conn->last_alive = time(0);
                        ikcp_input(conn->ikcp, (const char*)(tmp + 1), n - 1);
                        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
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
                        del_connection(conn);
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

    uint8_t            tmp[rd->max_pkt_size + 1];
    struct sockaddr_in addr;

    while (rd->thread_running) {
        int n =
            rd->recvfrom(rd->obj, &addr, tmp, sizeof(tmp), RECV_POLL_TIMEOUT);
        if (rd->conns[0]->connected) {
            time_t currtime = time_ms();
            RUN_OR_FAIL(pthread_mutex_lock(&rd->conns[0]->conn_lock));
            ikcp_update(rd->conns[0]->ikcp, currtime);
            RUN_OR_FAIL(pthread_mutex_unlock(&rd->conns[0]->conn_lock));
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
            continue;
        }
        switch (tmp[0]) {
            case PKT_CONN_ACK: {
                // conclude connection
                if (n != 1)
                    // malformed packet
                    continue;

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
                    continue;

                debug("thread_client_peer(): received DATA pkt");
                connection_t* conn = rd->conns[0];
                if (conn->connected &&
                    conn->peer.sin_addr.s_addr == addr.sin_addr.s_addr &&
                    conn->peer.sin_port == addr.sin_port) {
                    debug("thread_client_peer(): data dispatched [len: %d]",
                          n - 1);
                    RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
                    conn->last_alive = time(0);
                    ikcp_input(conn->ikcp, (const char*)(tmp + 1), n - 1);
                    RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
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
                    conn->connected    = 0;
                    rd->thread_running = 0;
                }
                break;
            }
            default:
                // unexpected packet
                break;
        }
    }

    rd->conns[0]->connected = 0;
    del_connection(rd->conns[0]);
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
    rd->conns[rd->conns_size] = mk_connection(addr, rd);
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

    rd->type               = TY_CLIENT_PEER;
    rd->conns              = btran_malloc(sizeof(connection_t*));
    rd->conns_size         = 1;
    rd->conns_capacity     = 1;
    rd->thread_running     = 1;
    rd->conns[0]           = mk_connection(addr, rd);
    rd->conns[0]->n_owners = 2;
    if (pthread_create(&rd->thread, NULL, &thread_client_peer, rd) != 0)
        return ERR_PTHREAD_CREATE_FAILED;

    rd->conns[0]->connected = 0;
    for (int i = 0; i < MAX_CONN_RETRY; ++i) {
        rd->sendto(rd->obj, addr, pkt_conn, sizeof(pkt_conn));
        msleep(CONN_RETRY_SLEEP_TIME);
        if (rd->conns[0]->connected)
            break;
    }
    if (!rd->conns[0]->connected) {
        reldgram_disconnect(rd);
        del_connection(rd->conns[0]);
        rd->conns_size = 0;
        return ERR_PEER_OFFLINE;
    }
    return NO_ERR;
}

int reldgram_send(reldgram_t* rd, const uint8_t* data, uint32_t data_size)
{
    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER)
        return ERR_WRONG_TYPE;
    if ((int)data_size < 0)
        return ERR_BUFFER_TOO_LONG;

    connection_t* conn = rd->conns[0];
    if (!conn->connected) {
        reldgram_disconnect(rd);
        return ERR_PEER_OFFLINE;
    }

    RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
    ikcp_send(conn->ikcp, (const char*)data, (int)data_size);
    RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
    return NO_ERR;
}

int reldgram_recv(reldgram_t* rd, uint8_t* data, uint32_t data_size,
                  uint32_t* nread)
{
    if (rd->type != TY_CLIENT_PEER && rd->type != TY_SERVER_PEER)
        return ERR_WRONG_TYPE;
    if ((int)data_size < 0)
        return ERR_BUFFER_TOO_LONG;

    debug("reldgram_recv(): waiting for data");
    connection_t* conn = rd->conns[0];
    int           r    = -1;
    while (conn->connected && r < 0) {
        RUN_OR_FAIL(pthread_mutex_lock(&conn->conn_lock));
        r = ikcp_recv(conn->ikcp, (char*)data, (int)data_size);
        RUN_OR_FAIL(pthread_mutex_unlock(&conn->conn_lock));
        if (r < 0)
            msleep(10);
    }
    if (!conn->connected) {
        reldgram_disconnect(rd);
        return ERR_PEER_OFFLINE;
    }

    debug("reldgram_recv(): data received [len: %d]", r);
    *nread = r;
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
