#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "udp.h"

#include "reldgram.h"
#include "alloc.h"
#include "log.h"

typedef struct udp_backend_t {
    reldgram_t* dgram_ctx;
    int         is_server_peer;
    int         fd;
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

int udp_backend_init(btran_ctx_t* ctx)
{
    ctx->ftab       = &udptab;
    ctx->backendptr = btran_calloc(sizeof(udp_backend_t));

    udp_backend_t* ub  = (udp_backend_t*)ctx->backendptr;
    ub->dgram_ctx      = NULL;
    ub->fd             = -1;
    ub->is_server_peer = 0;
    return 0;
}

static void udp_disconnect(btran_ctx_t* ctx)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->dgram_ctx)
        reldgram_disconnect(ub->dgram_ctx);
    if (ub->fd >= 0 && !ub->is_server_peer) {
        close(ub->fd);
        ub->fd = -1;
    }
}

static int udp_dispose(btran_ctx_t* ctx)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;

    if (ub->dgram_ctx)
        reldgram_destroy(ub->dgram_ctx);
    if (ub->fd >= 0 && !ub->is_server_peer)
        close(ub->fd);
    btran_free(ub);
    return 0;
}

static int udp_send_wrapper(void* user, struct sockaddr_in* addr,
                            const uint8_t* data, uint32_t data_size)
{
    // inject errors [ 10% pkt loss ]
    // if (rand() % 10 == 0)
    //     return -1;

    int fd = (long)user;
    return (int)sendto(fd, data, data_size, 0, (struct sockaddr*)addr,
                       sizeof(struct sockaddr_in));
}

static int udp_recv_wapper(void* user, struct sockaddr_in* addr, uint8_t* data,
                           uint32_t data_size, uint32_t timeout)
{
    int            fd       = (long)user;
    struct timeval wait     = {.tv_sec = 0, .tv_usec = timeout * 1000};
    socklen_t      addr_len = sizeof(struct sockaddr_in);

    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    if (select(fd + 1, &set, NULL, NULL, &wait) < 0)
        return -1;

    if (FD_ISSET(fd, &set))
        return (int)recvfrom(fd, data, data_size, 0, (struct sockaddr*)addr,
                             &addr_len);
    return -1;
}

static int udp_listen(btran_ctx_t* ctx, const char* addr, int port)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd != -1 || ub->dgram_ctx != NULL) {
        error("udp_listen(): invalid state");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error("udp_listen(): socket failed [%s]", strerror(errno));
        return 1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &bind_addr.sin_addr) != 1) {
        error("udp_listen(): inet_pton failed [%s]", strerror(errno));
        close(fd);
        return 1;
    }

    if (bind(fd, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        error("udp_listen(): bind failed [%s]", strerror(errno));
        close(fd);
        return 1;
    }

    ub->fd = fd;
    ub->dgram_ctx =
        reldgram_init((void*)(long)fd, &udp_send_wrapper, &udp_recv_wapper);
    if (ub->dgram_ctx == NULL) {
        error("udp_listen(): reldgram_init failed");
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }

    int r = reldgram_listen(ub->dgram_ctx);
    if (r != NO_ERR) {
        error("udp_listen(): reldgram_listen failed [%s]",
              reldgram_strerror(r));
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }
    return 0;
}

static int udp_connect(btran_ctx_t* ctx, const char* addr, int port)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd != -1 || ub->dgram_ctx != NULL) {
        error("udp_connect(): invalid state");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        error("udp_connect(): socket failed [%s]", strerror(errno));
        return 1;
    }

    ub->fd = fd;
    ub->dgram_ctx =
        reldgram_init((void*)(long)fd, &udp_send_wrapper, &udp_recv_wapper);
    if (ub->dgram_ctx == NULL) {
        error("udp_connect(): reldgram_init failed");
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &saddr.sin_addr) != 1) {
        error("udp_connect(): inet_pton failed [%s]", strerror(errno));
        return 1;
    }

    int r = reldgram_connect(ub->dgram_ctx, &saddr);
    if (r != NO_ERR) {
        error("udp_connect(): reldgram_connect failed [%s]",
              reldgram_strerror(r));
        return 1;
    }
    return 0;
}

static int udp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("udp_accept(): invalid state");
        return 1;
    }

    reldgram_t* client = reldgram_accept(ub->dgram_ctx);
    if (client == NULL) {
        error("udp_accept(): reldgram_accept failed");
        return 1;
    }

    udp_backend_init(o_conn);
    ((udp_backend_t*)o_conn->backendptr)->dgram_ctx      = client;
    ((udp_backend_t*)o_conn->backendptr)->fd             = ub->fd;
    ((udp_backend_t*)o_conn->backendptr)->is_server_peer = 1;
    return 0;
}

static int udp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nread, uint32_t timeout)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("udp_recv(): invalid state");
        return 1;
    }

    int r = reldgram_recv(ub->dgram_ctx, buf, buf_size, nread);
    if (r != NO_ERR) {
        error("udp_recv(): reldgram_recv failed [%s]", reldgram_strerror(r));
        return 1;
    }
    return 0;
}

static int udp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                    uint32_t* nsent)
{
    udp_backend_t* ub = (udp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("udp_send(): invalid state");
        return 1;
    }

    int r = reldgram_send(ub->dgram_ctx, buf, buf_size);
    if (r != NO_ERR) {
        error("udp_send(): reldgram_send failed [%s]", reldgram_strerror(r));
        return 1;
    }
    *nsent = buf_size;
    return 0;
}
