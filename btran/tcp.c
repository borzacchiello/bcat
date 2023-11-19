#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "alloc.h"
#include "log.h"
#include "tcp.h"

#define QUEUE_SIZE 8

typedef struct tcp_backend_t {
    int fd;
} tcp_backend_t;

static int  tcp_dispose(btran_ctx_t* ctx);
static void tcp_disconnect(btran_ctx_t* ctx);
static int  tcp_listen(btran_ctx_t* ctx, const char* addr, int port);
static int  tcp_connect(btran_ctx_t* ctx, const char* addr, int port);
static int  tcp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn);
static int  tcp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nread, uint32_t timeout);
static int  tcp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nsent);

static const btran_ftab_t tcptab = {.dispose    = tcp_dispose,
                                    .disconnect = tcp_disconnect,
                                    .listen     = tcp_listen,
                                    .connect    = tcp_connect,
                                    .accept     = tcp_accept,
                                    .recv       = tcp_recv,
                                    .send       = tcp_send};

int tcp_backend_init(btran_ctx_t* ctx)
{
    ctx->ftab       = &tcptab;
    ctx->backendptr = btran_malloc(sizeof(tcp_backend_t));

    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    tb->fd            = -1;
    return 0;
}

static int tcp_dispose(btran_ctx_t* ctx)
{
    tcp_disconnect(ctx);

    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    btran_free(tb);
    return 0;
}

static void tcp_disconnect(btran_ctx_t* ctx)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd > 0) {
        shutdown(tb->fd, SHUT_RDWR);
        close(tb->fd);
        tb->fd = -1;
    }
}

static int tcp_listen(btran_ctx_t* ctx, const char* addr, int port)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd != -1) {
        error("tcp_listen(): descriptor is not -1");
        return 1;
    }

    tb->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tb->fd < 0) {
        int r = errno;
        error("tcp_listen() socket failed: %s", strerror(r));
        return r;
    }

    int option = 1;
    setsockopt(tb->fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &sockaddr.sin_addr) <= 0) {
        int r = errno;
        error("tcp_listen() inet_pton failed: %s", strerror(r));
        return r;
    }

    if (bind(tb->fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        int r = errno;
        error("tcp_listen() bind failed: %s", strerror(r));
        return r;
    }

    if (listen(tb->fd, QUEUE_SIZE) < 0) {
        int r = errno;
        error("tcp_listen() listen failed: %s", strerror(r));
        return r;
    }

    info("tcp: listening on %s:%d", addr, port);
    return 0;
}

static int tcp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd == -1) {
        error("tcp_accept(): descriptor is -1");
        return 1;
    }

    struct sockaddr_in client_addr;
    int                client_fd;
    socklen_t          client_addr_len = sizeof(client_addr);

    client_fd =
        accept(tb->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        int r = errno;
        error("tcp_accept() accept failed: %s", strerror(r));
        return r;
    }

    char client_addr_str[INET_ADDRSTRLEN + 1] = {0};
    if (inet_ntop(AF_INET, &client_addr.sin_addr, client_addr_str,
                  INET_ADDRSTRLEN) == NULL) {
        int r = errno;
        error("tcp_accept() inet_ntop failed: %s", strerror(r));
        return r;
    }

    info("tcp: connection accepted from %s", (const char*)client_addr_str);
    tcp_backend_init(o_conn);
    ((tcp_backend_t*)o_conn->backendptr)->fd = client_fd;
    return 0;
}

static int tcp_connect(btran_ctx_t* ctx, const char* addr, int port)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd != -1) {
        error("tcp_connect(): descriptor is not -1");
        return 1;
    }

    tb->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tb->fd < 0) {
        int r = errno;
        error("tcp_connect() socket failed: %s", strerror(r));
        return r;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family         = AF_INET;
    server_addr.sin_port           = htons(port);
    if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
        int r = errno;
        error("tcp_connect() inet_pton failed: %s", strerror(r));
        return r;
    }

    if (connect(tb->fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) ==
        -1) {
        int r = errno;
        error("tcp_connect() connect failed: %s", strerror(r));
        return r;
    }

    info("tcp: connected to %s:%d", addr, port);
    return 0;
}

static int tcp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nread, uint32_t timeout)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd == -1) {
        error("tcp_recv(): descriptor is -1");
        return 1;
    }

    if (timeout) {
        struct timeval wait = {.tv_sec = timeout, .tv_usec = 0};
        fd_set         set;
        FD_ZERO(&set);
        FD_SET(tb->fd, &set);
        if (select(tb->fd + 1, &set, NULL, NULL, &wait) <= 0)
            return 1;
    }
    ssize_t received = recv(tb->fd, buf, buf_size, 0);
    if (received < 0) {
        int r = errno;
        error("tcp_recv() recv failed: %s", strerror(r));
        return r;
    }
    if (received == 0)
        // FIN pkt received
        return 1;

    *nread = (uint32_t)received;
    return 0;
}

static int tcp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nsent)
{
    tcp_backend_t* tb = (tcp_backend_t*)ctx->backendptr;
    if (tb->fd == -1) {
        error("tcp_send(): descriptor is -1");
        return 1;
    }

    ssize_t sent = send(tb->fd, buf, buf_size, 0);
    if (sent < 0) {
        int r = errno;
        error("tcp_send() send failed: %s", strerror(r));
        return r;
    }

    *nsent = (uint64_t)sent;
    return 0;
}
