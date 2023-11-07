#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "udp.h"

#include "alloc.h"
#include "ikcp.h"
#include "log.h"
#include "ll.h"

#define RECV_BUFFER_CAPACITY (1024 * 100)
#define TIME_MS              1000ul

#define ACCEPT_QUEUE_MAX_SIZE      10
#define MAX_CONCURRENT_CONNECTIONS 16

#define SYN_DATA "4242"

typedef enum backend_ty_t {
    UNKOWN            = 0,
    SERVER_ACCEPT     = 1,
    SERVER_CONNECTION = 2,
    CLIENT            = 3,
} backend_ty_t;

typedef struct udp_backend_t {
    int          fd;
    backend_ty_t ty;
    union {
        struct {
            pthread_t listen_thread;
            int       listen_thread_should_run;

            pthread_mutex_t       accept_sem;
            LL                    accept_queue;
            struct udp_backend_t* connections;
        };
        struct {
            pthread_mutex_t    conn_sem;
            uint8_t            connected;
            struct sockaddr_in peer_addr;
            ikcpcb*            ikcp_ctx;
            pthread_t          ikcp_update_thread;
            int                client_thread_should_run;
        };
    };
} udp_backend_t;

static int  udp_dispose(btran_ctx_t* ctx);
static void udp_disconnect(btran_ctx_t* ctx);
static int  udp_listen(btran_ctx_t* ctx, const char* addr, int port);
static int  udp_connect(btran_ctx_t* ctx, const char* addr, int port);
static int  udp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn);
static int  udp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nread, uint32_t timeout);
static int  udp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nsent);

static const btran_ftab_t udptab = {.dispose    = udp_dispose,
                                    .disconnect = udp_disconnect,
                                    .listen     = udp_listen,
                                    .connect    = udp_connect,
                                    .accept     = udp_accept,
                                    .recv       = udp_recv,
                                    .send       = udp_send};

static uint64_t get_time_ms()
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);

    return spec.tv_nsec / TIME_MS;
}

static int output_callback(const char* buf, int len, ikcpcb* kcp, void* user)
{
    udp_backend_t* ub = user;
    (void)kcp;

    int sent = 0;
    while (sent < len) {
        int n;
        if ((n = sendto(ub->fd, buf + sent, len - sent, 0,
                        (struct sockaddr*)&ub->peer_addr,
                        sizeof(struct sockaddr_in))) < 0) {
            int r = errno;
            error("output_callback(): send failed [%s]", strerror(errno));
            return r;
        }
        sent += n;
    }
    return 0;
}

// **** BEGIN THREADS ****
static void* ikcp_update_thread(void* _ub)
{
    udp_backend_t* ub = _ub;
    while (ub->client_thread_should_run) {
        ikcp_update(ub->ikcp_ctx, get_time_ms());
        usleep(100 * TIME_MS);
    }
    return NULL;
}

static void* listen_thread(void* _ub)
{
    // This thread dispaches incoming requests between active connections or put
    // them in the "accept" queue
    udp_backend_t* ub = _ub;
    if (ub->ty != SERVER_ACCEPT)
        panic("listen_thread(): wrong type %d", ub->ty);

    debug("listen_thread(): running...");

    uint8_t buf[1024];
    while (ub->listen_thread_should_run) {
        struct sockaddr_in client_addr;
        socklen_t          addr_len = sizeof(client_addr);

        debug("listen_thread(): waiting for packet");
        ssize_t n = recvfrom(ub->fd, buf, 1024, 0,
                             (struct sockaddr*)&client_addr, &addr_len);
        if (n < 0) {
            error("listen_thread(): recvfrom failed");
            break;
        }
        debug("listen_thread(): packet with size %d received from %08x:%d", n,
              client_addr.sin_addr.s_addr, client_addr.sin_port);

        int is_syn = 0;
        if (n == sizeof(SYN_DATA) - 1 &&
            memcmp(buf, SYN_DATA, sizeof(SYN_DATA) - 1) == 0)
            is_syn = 1;

        int handled = 0;
        for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; ++i) {
            udp_backend_t* c = &ub->connections[i];
            // a fast-path before taking the lock
            if (!c->connected)
                continue;

            // take the connection lock, and dispatch the message to the correct
            // object
            if (pthread_mutex_lock(&c->conn_sem) != 0)
                panic("listen_thread(): unable to wait on semaphore conn_sem "
                      "[%s]",
                      strerror(errno));
            if (!c->connected) {
                if (pthread_mutex_unlock(&c->conn_sem) != 0)
                    panic("listen_thread(): unable to release semaphore "
                          "conn_sem [%s]",
                          strerror(errno));
                continue;
            }
            if (c->peer_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
                c->peer_addr.sin_port == client_addr.sin_port) {

                debug("listen_thread(): dispatching to an active connection");
                if (!is_syn)
                    ikcp_input(c->ikcp_ctx, (const char*)buf, n);
                else {
                    // a duplicate SYN packet, redending...
                    info("listen_thread(): received a duplicate SYN packet, "
                         "resending ACK");
                    sendto(ub->fd, SYN_DATA, sizeof(SYN_DATA) - 1, 0,
                           (struct sockaddr*)&client_addr, addr_len);
                }
                handled = 1;
            }
            if (pthread_mutex_unlock(&c->conn_sem) != 0)
                panic("listen_thread(): unable to release semaphore "
                      "conn_sem [%s]",
                      strerror(errno));
            if (handled)
                break;
        }
        if (handled)
            continue;

        if (!is_syn) {
            error("listen_thread(): unexpected packet, expecting SYN");
            continue;
        }

        // A fresh new connection, add it to the "accept queue"
        if (pthread_mutex_lock(&ub->accept_sem) != 0)
            panic("listen_thread(): unable to wait on semaphore [%s]",
                  strerror(errno));
        if (ub->accept_queue.size >= ACCEPT_QUEUE_MAX_SIZE) {
            warning("listen_thread(): dropped connection because accept queue "
                    "is full");
            if (pthread_mutex_unlock(&ub->accept_sem) != 0)
                panic(
                    "listen_thread(): unable release semaphore accept_sem [%s]",
                    strerror(errno));
            continue;
        }
        struct sockaddr_in* c = btran_calloc(sizeof(struct sockaddr_in));
        *c                    = client_addr;
        ll_add(&ub->accept_queue, (uintptr_t)c);

        if (pthread_mutex_unlock(&ub->accept_sem) != 0)
            panic("listen_thread(): unable release mutex accept_sem [%s]",
                  strerror(errno));
    }
    return NULL;
}
// **** END THREADS ****

int udp_backend_init(btran_ctx_t* ctx)
{
    ctx->ftab       = &udptab;
    ctx->backendptr = btran_calloc(sizeof(udp_backend_t));

    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    ub->fd            = -1;
    return 0;
}

static int udp_dispose(btran_ctx_t* ctx)
{
    udp_disconnect(ctx);

    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    switch (ub->ty) {
        case SERVER_ACCEPT:
            for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; ++i) {
                udp_backend_t* c = &ub->connections[i];
                pthread_mutex_destroy(&c->conn_sem);
            }
            pthread_mutex_destroy(&ub->accept_sem);
            btran_free(ub->connections);
            btran_free(ub);
            break;
        case SERVER_CONNECTION:
            break;
        case CLIENT:
            btran_free(ub);
            break;
        default:
            error("udp_dispose(): disposing an uninitialized backend");
            return 1;
    }
    return 0;
}

static void udp_disconnect(btran_ctx_t* ctx)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;

    switch (ub->ty) {
        case SERVER_ACCEPT: {
            ub->listen_thread_should_run = 0;
            pthread_join(ub->listen_thread, NULL);
            ll_clear(&ub->accept_queue, (func_on_el_t)btran_free);

            for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; ++i) {
                udp_backend_t* c = &ub->connections[i];

                if (c->connected) {
                    c->connected                = 0;
                    c->client_thread_should_run = 0;
                    pthread_join(c->ikcp_update_thread, NULL);
                }
            }
            break;
        }
        case SERVER_CONNECTION:
            if (ub->connected) {
                if (pthread_mutex_lock(&ub->conn_sem) != 0)
                    panic("udp_disconnect(): unable to wait on semaphore "
                          "conn_sem "
                          "[%s]",
                          strerror(errno));
                ub->connected                = 0;
                ub->client_thread_should_run = 0;
                if (pthread_mutex_unlock(&ub->conn_sem) != 0)
                    panic("udp_disconnect(): unable to release semaphore "
                          "conn_sem "
                          "[%s]",
                          strerror(errno));
                pthread_join(ub->ikcp_update_thread, NULL);
                ikcp_release(ub->ikcp_ctx);
            }
            break;
        case CLIENT:
            if (ub->connected) {
                ub->connected                = 0;
                ub->client_thread_should_run = 0;
                pthread_join(ub->ikcp_update_thread, NULL);
                ikcp_release(ub->ikcp_ctx);
            }
            break;
        default:
            error("udp_disconnect(): disconnecting an uninitialized backend");
            return;
    }
    if (ub->fd >= 0)
        close(ub->fd);
    ub->fd = -1;
}

static int udp_listen(btran_ctx_t* ctx, const char* addr, int port)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd != -1) {
        error("udp_listen(): descriptor is not -1");
        return 1;
    }

    ub->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ub->fd < 0) {
        int r = errno;
        error("udp_listen(): socket failed [%s]", strerror(r));
        return r;
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &saddr.sin_addr) <= 0) {
        int r = errno;
        error("udp_listen(): inet_pton failed [%s]", strerror(r));
        return r;
    }
    if (bind(ub->fd, (const struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        int r = errno;
        error("udp_listen(): bind failed [%s]", strerror(r));
        return r;
    }

    if (pthread_mutex_init(&ub->accept_sem, NULL) != 0)
        panic("udp_listen(): unable to initialize accept_sem");

    ub->ty           = SERVER_ACCEPT;
    ub->accept_queue = ll_create();
    ub->connections =
        btran_calloc(sizeof(udp_backend_t) * MAX_CONCURRENT_CONNECTIONS);
    for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; ++i) {
        udp_backend_t* c = &ub->connections[i];

        c->connected = 0;
        c->fd        = -1;
        if (pthread_mutex_init(&c->conn_sem, NULL) != 0)
            panic("udp_listen(): unable to initialize connection semaphore");
    }
    ub->listen_thread_should_run = 1;
    if (pthread_create(&ub->listen_thread, NULL, &listen_thread, ub) != 0)
        panic("udp_listen(): pthread_create failed [%s]", strerror(errno));
    return 0;
}

static int udp_connect(btran_ctx_t* ctx, const char* addr, int port)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd != -1) {
        error("udp_connect(): descriptor is not -1");
        return 1;
    }

    ub->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ub->fd < 0) {
        int r = errno;
        error("udp_connect(): socket failed [%s]", strerror(r));
        return r;
    }

    struct sockaddr_in saddr;
    socklen_t          addr_len = sizeof(saddr);
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &saddr.sin_addr) <= 0) {
        int r = errno;
        error("udp_connect(): inet_pton failed [%s]", strerror(r));
        return r;
    }

    // ** FIXME ** should handle retransmission, and timeout
    for (int i = 0; i < 3; ++i)
        // FIXME: ugly as fuck
        if (sendto(ub->fd, SYN_DATA, sizeof(SYN_DATA) - 1, 0,
                   (struct sockaddr*)&saddr,
                   addr_len) != sizeof(SYN_DATA) - 1) {
            error("udp_connect(): SYN send failed");
            return 1;
        }

    uint8_t buf[128];
    ssize_t n = recvfrom(ub->fd, buf, sizeof(buf), 0, (struct sockaddr*)&saddr,
                         &addr_len);
    if (n < 0) {
        error("udp_connect(): SYN-ACK recv failed");
        return 1;
    }
    if (n != sizeof(SYN_DATA) - 1 ||
        memcmp(buf, SYN_DATA, sizeof(SYN_DATA) - 1) != 0) {
        error("udp_connect(): unexpected packet, expecting SYN-ACK");
        return 1;
    }

    ub->connected                = 1;
    ub->ty                       = CLIENT;
    ub->ikcp_ctx                 = ikcp_create(31337, ub);
    ub->client_thread_should_run = 1;
    ub->peer_addr                = saddr;
    ikcp_setoutput(ub->ikcp_ctx, output_callback);
    if (pthread_create(&ub->ikcp_update_thread, NULL, &ikcp_update_thread,
                       ub) != 0)
        panic("udp_connect(): pthread_create failed");
    return 0;
}

static int udp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd == -1) {
        error("udp_accept(): descriptor is -1");
        return 1;
    }
    if (ub->ty != SERVER_ACCEPT) {
        error("udp_accept(): wrong type %d", ub->ty);
        return 1;
    }
    debug("udp_accept(): waiting for connections...");

    LLNode* node = NULL;
    while (1) {
        if (pthread_mutex_lock(&ub->accept_sem) != 0)
            panic("udp_accept(): unable to wait on semaphore [%s]",
                  strerror(errno));

        if (ub->accept_queue.size > 0) {
            node = ll_pop(&ub->accept_queue);
            if (pthread_mutex_unlock(&ub->accept_sem) != 0)
                panic("udp_accept(): unable to release semaphore [%s]",
                      strerror(errno));
            break;
        }
        if (pthread_mutex_unlock(&ub->accept_sem) != 0)
            panic("udp_accept(): unable to release semaphore [%s]",
                  strerror(errno));
        usleep(100 * TIME_MS);
    }

    struct sockaddr_in addr = *(struct sockaddr_in*)node->data;
    debug("udp_accept(): new connection from %08x:%d", addr.sin_addr.s_addr,
          addr.sin_port);

    int            handled = 0;
    udp_backend_t* c       = NULL;
    for (int i = 0; i < MAX_CONCURRENT_CONNECTIONS; ++i) {
        c = &ub->connections[i];
        if (c->connected)
            continue;

        if (pthread_mutex_lock(&c->conn_sem) != 0)
            panic("udp_accept(): unable to wait on semaphore conn_sem "
                  "[%s]",
                  strerror(errno));
        if (c->connected) {
            if (pthread_mutex_unlock(&c->conn_sem) != 0)
                panic("udp_accept(): unable to release semaphore conn_sem "
                      "[%s]",
                      strerror(errno));
            continue;
        }

        o_conn->backendptr = (udp_backend_t*)c;
        o_conn->ftab       = &udptab;
        handled            = 1;

        c->ty                       = SERVER_CONNECTION;
        c->fd                       = ub->fd;
        c->connected                = 1;
        c->peer_addr                = *(struct sockaddr_in*)node->data;
        c->ikcp_ctx                 = ikcp_create(31337, c);
        c->client_thread_should_run = 1;
        ikcp_setoutput(c->ikcp_ctx, output_callback);
        if (pthread_create(&c->ikcp_update_thread, NULL, &ikcp_update_thread,
                           c) != 0)
            panic("udp_accept(): unable to create client thread");

        if (pthread_mutex_unlock(&c->conn_sem) != 0)
            panic("udp_accept(): unable to release semaphore conn_sem "
                  "[%s]",
                  strerror(errno));
        break;
    }

    btran_free((void*)node->data);
    btran_free(node);

    if (!handled) {
        error("udp_accept(): not enough room for a new connection");
        return 1;
    }

    info("udp_accept(): sending SYN-ACK");
    for (int i = 0; i < 3; ++i)
        // FIXME: ugly as fuck
        if (sendto(ub->fd, SYN_DATA, sizeof(SYN_DATA) - 1, 0,
                   (struct sockaddr*)&c->peer_addr,
                   sizeof(struct sockaddr_in)) != sizeof(SYN_DATA) - 1) {
            error("listen_thread(): SYN-ACK send failed");
            return 1;
        }
    return 0;
}

static int udp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nread, uint32_t timeout)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->ty == SERVER_ACCEPT || !ub->connected)
        return 1;

    switch (ub->ty) {
        case CLIENT: {
            uint8_t   tmp[1024];
            socklen_t addr_len = sizeof(struct sockaddr_in);
            ssize_t   n        = 0;
            while (1) {
                ssize_t n =
                    recvfrom(ub->fd, tmp, sizeof(tmp), 0,
                             (struct sockaddr*)&ub->peer_addr, &addr_len);
                if (n < 0)
                    return n;
                if (n == sizeof(SYN_DATA) - 1 &&
                    memcmp(tmp, SYN_DATA, sizeof(SYN_DATA) - 1) == 0)
                    continue;
                break;
            }
            ikcp_input(ub->ikcp_ctx, (char*)tmp, n);
            int r = 0;
            while (r <= 0) {
                r = ikcp_recv(ub->ikcp_ctx, (char*)buf, buf_size);
                if (r > 0) {
                    *nread = r;
                    return 0;
                }
                usleep(10 * TIME_MS);
            }
        }
        case SERVER_CONNECTION: {
            int r = 0;
            while (r <= 0) {
                r = ikcp_recv(ub->ikcp_ctx, (char*)buf, buf_size);
                // debug("udp_recv(): ikcp_recv return value: %d", r);
                if (r > 0) {
                    *nread = r;
                    debug("udp_recv(): ikcp_recv received %d bytes", r);
                    return 0;
                }
                usleep(10 * TIME_MS);
            }
        }
        default:
            break;
    }
    return 1;
}

static int udp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nsent)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->ty == SERVER_ACCEPT || !ub->connected)
        return 1;

    switch (ub->ty) {
        case CLIENT:
        case SERVER_CONNECTION: {
            int r = ikcp_send(ub->ikcp_ctx, (char*)buf, buf_size);
            if (r < 0)
                return 1;
            *nsent = r;
            return 0;
        }
        default:
            break;
    }
    return 1;
}
