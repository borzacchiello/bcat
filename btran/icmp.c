// pkt construction taken from:
// https://github.com/DhavalKapil/icmptunnel/tree/master

#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "icmp.h"

#include "reldgram.h"
#include "alloc.h"
#include "log.h"

// Maximum transmission unit
#define MTU 1472

typedef struct icmp_backend_t {
    reldgram_t* dgram_ctx;
    int         is_server_peer;

    int                fd;
    int                is_server;
    struct sockaddr_in my_addr;
    uint16_t           port;
} icmp_backend_t;

static int  icmp_dispose(btran_ctx_t* ctx);
static void icmp_disconnect(btran_ctx_t* ctx);
static int  icmp_listen(btran_ctx_t* ctx, const char* addr, int port);
static int  icmp_connect(btran_ctx_t* ctx, const char* addr, int port);
static int  icmp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn);
static int  icmp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                      uint32_t* nread, uint32_t timeout);
static int  icmp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                      uint32_t* nsent);

static const btran_ftab_t icmptab = {.dispose    = icmp_dispose,
                                     .disconnect = icmp_disconnect,
                                     .listen     = icmp_listen,
                                     .connect    = icmp_connect,
                                     .accept     = icmp_accept,
                                     .recv       = icmp_recv,
                                     .send       = icmp_send};

int icmp_backend_init(btran_ctx_t* ctx)
{
    ctx->ftab       = &icmptab;
    ctx->backendptr = btran_calloc(sizeof(icmp_backend_t));

    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    ub->dgram_ctx      = NULL;
    ub->fd             = -1;
    ub->port           = -1;
    ub->is_server_peer = 0;
    return 0;
}

static void icmp_disconnect(btran_ctx_t* ctx)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->dgram_ctx)
        reldgram_disconnect(ub->dgram_ctx);
    if (ub->fd >= 0 && !ub->is_server_peer) {
        close(ub->fd);
        ub->fd = -1;
    }
}

static int icmp_dispose(btran_ctx_t* ctx)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;

    if (ub->dgram_ctx)
        reldgram_destroy(ub->dgram_ctx);
    if (ub->fd >= 0 && !ub->is_server_peer)
        close(ub->fd);
    btran_free(ub);
    return 0;
}

static void prepare_headers(struct iphdr* ip, struct icmphdr* icmp)
{
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->id       = rand();
    ip->frag_off = 0;
    ip->ttl      = 255;
    ip->protocol = IPPROTO_ICMP;

    icmp->code             = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id       = rand();
    icmp->checksum         = 0;
}

static uint16_t in_cksum(uint16_t* addr, int len)
{
    int       nleft  = len;
    uint32_t  sum    = 0;
    uint16_t* w      = addr;
    uint16_t  answer = 0;

    // Adding 16 bits sequentially in sum
    while (nleft > 1) {
        sum += *w;
        nleft -= 2;
        w++;
    }

    // If an odd byte is left
    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

static int icmp_send_wrapper(void* user, struct sockaddr_in* addr,
                             const uint8_t* data, uint32_t data_size)
{
    icmp_backend_t* ub = (icmp_backend_t*)user;
    debug("icmp_send_wrapper(): sending icmp packet with size %u [src port %u]",
          data_size, ub->port);

    struct in_addr src_addr  = ub->my_addr.sin_addr;
    struct in_addr dest_addr = addr->sin_addr;

    uint16_t src_port = htons(ub->port);
    uint16_t dst_port = addr->sin_port;

    int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) +
                      2 * sizeof(uint16_t) + data_size;
    char* packet = btran_calloc(packet_size);

    struct iphdr*   ip   = (struct iphdr*)packet;
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
    uint16_t*       icmp_payload_src_port =
        (uint16_t*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    uint16_t* icmp_payload_dst_port =
        (uint16_t*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) +
                    sizeof(uint16_t));
    char* icmp_payload = (char*)(packet + sizeof(struct iphdr) +
                                 sizeof(struct icmphdr) + 2 * sizeof(uint16_t));

    prepare_headers(ip, icmp);
    *icmp_payload_src_port = src_port;
    *icmp_payload_dst_port = dst_port;

    ip->tot_len = htons(packet_size);
    ip->saddr   = src_addr.s_addr;
    ip->daddr   = dest_addr.s_addr;
    memcpy(icmp_payload, data, data_size);

    icmp->type = ub->is_server ? ICMP_ECHOREPLY : ICMP_ECHO;
    icmp->checksum =
        in_cksum((unsigned short*)icmp,
                 sizeof(struct icmphdr) + 2 * sizeof(uint16_t) + data_size);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = dest_addr.s_addr;

    int r =
        (int)sendto(ub->fd, packet, packet_size, 0, (struct sockaddr*)&servaddr,
                    sizeof(struct sockaddr_in));
    btran_free(packet);
    return r;
}

static int icmp_recv_wapper(void* user, struct sockaddr_in* addr, uint8_t* data,
                            uint32_t data_size, uint32_t timeout)
{
    icmp_backend_t* ub = (icmp_backend_t*)user;

    struct timeval wait = {.tv_sec = 0, .tv_usec = timeout * 1000};
    fd_set         set;
    FD_ZERO(&set);
    FD_SET(ub->fd, &set);
    if (select(ub->fd + 1, &set, NULL, NULL, &wait) <= 0)
        return -1;

    int enc_MTU =
        MTU + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(uint16_t);
    char* packet = btran_calloc(enc_MTU);

    struct sockaddr_in src_addr;
    socklen_t          src_addr_size = sizeof(struct sockaddr_in);
    int                packet_size   = recvfrom(ub->fd, packet, enc_MTU, 0,
                                                (struct sockaddr*)&(src_addr), &src_addr_size);

    struct iphdr* ip = (struct iphdr*)packet;
    // struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
    uint16_t* icmp_payload_src_port =
        (uint16_t*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    uint16_t* icmp_payload_dst_port =
        (uint16_t*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr) +
                    sizeof(uint16_t));
    char* icmp_payload = (char*)(packet + sizeof(struct iphdr) +
                                 sizeof(struct icmphdr) + 2 * sizeof(uint16_t));

    debug("received packet with srcport: %u, dstport: %u, myport: %u",
          ntohs(*icmp_payload_src_port), ntohs(*icmp_payload_dst_port),
          ub->port);

    if (ntohs(*icmp_payload_dst_port) != ub->port) {
        btran_free(packet);
        return -1;
    }

    addr->sin_addr.s_addr = ip->saddr;
    addr->sin_port        = *icmp_payload_src_port;

    int payload_size = packet_size - sizeof(struct iphdr) -
                       sizeof(struct icmphdr) - 2 * sizeof(uint16_t);
    if (payload_size < 0 || (uint32_t)payload_size > data_size)
        panic("icmp_recv_wapper(): not enough space to hold the data "
              "[payload_size: %d, data_size: %u]",
              payload_size, data_size);
    memcpy(data, icmp_payload, payload_size);

    free(packet);
    return payload_size;
}

static int icmp_listen(btran_ctx_t* ctx, const char* addr, int port)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->fd != -1 || ub->dgram_ctx != NULL) {
        error("icmp_listen(): invalid state");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        error("icmp_listen(): socket failed [%s]", strerror(errno));
        return 1;
    }
    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) ==
        -1) {
        error("icmp_listen(): setsockopt failed [%s]", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port   = 0;
    if (inet_pton(AF_INET, addr, &bind_addr.sin_addr) != 1) {
        error("icmp_listen(): inet_pton failed [%s]", strerror(errno));
        close(fd);
        return 1;
    }
    if (bind(fd, (const struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        error("icmp_listen(): bind failed [%s]", strerror(errno));
        close(fd);
        return 1;
    }
    socklen_t addrlen = sizeof(ub->my_addr);
    if (getsockname(fd, (struct sockaddr*)&ub->my_addr, &addrlen) != 0) {
        error("icmp_listen(): getsockname failed [%s]", strerror(errno));
        close(fd);
        return 1;
    }

    ub->port = port;
    ub->fd   = fd;
    ub->dgram_ctx =
        reldgram_init((void*)ub, &icmp_send_wrapper, &icmp_recv_wapper);
    if (ub->dgram_ctx == NULL) {
        error("icmp_listen(): reldgram_init failed");
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }
    ub->dgram_ctx->max_pkt_size = 400;

    ub->is_server = 1;
    int r         = reldgram_listen(ub->dgram_ctx);
    if (r != NO_ERR) {
        error("icmp_listen(): reldgram_listen failed [%s]",
              reldgram_strerror(r));
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }
    return 0;
}

static int icmp_connect(btran_ctx_t* ctx, const char* addr, int port)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->fd != -1 || ub->dgram_ctx != NULL) {
        error("icmp_connect(): invalid state");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        error("icmp_connect(): socket failed [%s]", strerror(errno));
        return 1;
    }
    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) ==
        -1) {
        error("icmp_listen(): setsockopt failed [%s]", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (getentropy((void*)&ub->port, sizeof(ub->port)) != 0)
        panic("icmp_connect(): unable to generate random port");
    ub->fd = fd;
    ub->dgram_ctx =
        reldgram_init((void*)ub, &icmp_send_wrapper, &icmp_recv_wapper);
    if (ub->dgram_ctx == NULL) {
        error("icmp_connect(): reldgram_init failed");
        close(ub->fd);
        ub->fd = -1;
        return 1;
    }
    ub->dgram_ctx->max_pkt_size = 400;

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &saddr.sin_addr) != 1) {
        error("icmp_connect(): inet_pton failed [%s]", strerror(errno));
        return 1;
    }

    ub->is_server = 0;
    int r         = reldgram_connect(ub->dgram_ctx, &saddr);
    if (r != NO_ERR) {
        error("icmp_connect(): reldgram_connect failed [%s]",
              reldgram_strerror(r));
        return 1;
    }
    return 0;
}

static int icmp_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("icmp_accept(): invalid state");
        return 1;
    }

    reldgram_t* client = reldgram_accept(ub->dgram_ctx);
    if (client == NULL) {
        error("icmp_accept(): reldgram_accept failed");
        return 1;
    }

    icmp_backend_init(o_conn);
    ((icmp_backend_t*)o_conn->backendptr)->dgram_ctx      = client;
    ((icmp_backend_t*)o_conn->backendptr)->fd             = ub->fd;
    ((icmp_backend_t*)o_conn->backendptr)->port           = ub->port;
    ((icmp_backend_t*)o_conn->backendptr)->is_server_peer = 1;
    ((icmp_backend_t*)o_conn->backendptr)->is_server      = 1;
    return 0;
}

static int icmp_recv(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nread, uint32_t timeout)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("icmp_recv(): invalid state");
        return 1;
    }

    int r = reldgram_recv(ub->dgram_ctx, buf, buf_size, nread, timeout);
    if (r != NO_ERR) {
        error("icmp_recv(): reldgram_recv failed [%s]", reldgram_strerror(r));
        return 1;
    }
    return 0;
}

static int icmp_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                     uint32_t* nsent)
{
    icmp_backend_t* ub = (icmp_backend_t*)ctx->backendptr;
    if (ub->fd == -1 || ub->dgram_ctx == NULL) {
        error("icmp_send(): invalid state");
        return 1;
    }

    int r = reldgram_send(ub->dgram_ctx, buf, buf_size);
    if (r != NO_ERR) {
        error("icmp_send(): reldgram_send failed [%s]", reldgram_strerror(r));
        return 1;
    }
    *nsent = buf_size;
    return 0;
}
