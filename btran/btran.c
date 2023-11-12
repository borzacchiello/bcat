#include <sys/random.h>
#include <arpa/inet.h>
#include <string.h>

#include "salsa20.h"
#include "sha256.h"
#include "btran.h"
#include "alloc.h"
#include "log.h"

#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#define AUTH_TIMEOUT 3

static int recv_uint32_t(btran_ctx_t* ctx, uint32_t* data, uint32_t timeout);
static int send_uint32_t(btran_ctx_t* ctx, uint32_t data);

static void fill_with_random(uint8_t* buffer, uint32_t size)
{
    if (getentropy(buffer, size) != 0)
        panic("unable to generate random data");
}

__attribute__((unused)) static char nibble_to_hex(uint8_t v)
{
    v &= 0xf;
    if (v < 10)
        return '0' + v;
    return 'a' + (v - 10);
}

__attribute__((unused)) static char* buffer_to_string(uint8_t* buf,
                                                      size_t   buf_size)
{
    char* out = btran_calloc(buf_size * 2 + 1);
    for (size_t i = 0; i < buf_size; ++i) {
        out[i * 2]     = nibble_to_hex(buf[i] >> 4);
        out[i * 2 + 1] = nibble_to_hex(buf[i] & 0xf);
    }
    return out;
}

int btran_init(btran_ctx_t* ctx, btran_backend_t type, const char* key)
{
    ctx->session_token = 0;
    ctx->ty            = type;
    switch (type) {
        case BTRAN_TCP:
            tcp_backend_init(ctx);
            break;
        case BTRAN_UDP:
            udp_backend_init(ctx);
            break;
        case BTRAN_ICMP:
            icmp_backend_init(ctx);
            break;
        default:
            error("invalid backend type %d", type);
            return 1;
    }

    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, (uint8_t*)key, strlen(key));
    sha256_final(&sha_ctx, ctx->key_hash);
    return 0;
}

void btran_dispose(btran_ctx_t* ctx) { ctx->ftab->dispose(ctx); }

void btran_disconnect(btran_ctx_t* ctx) { ctx->ftab->disconnect(ctx); }

int btran_listen(btran_ctx_t* ctx, const char* addr, int port)
{
    return ctx->ftab->listen(ctx, addr, port);
}

static int exchange_key(btran_ctx_t* ctx)
{
    uint8_t new_key[32];
    uint8_t new_key_enc[32];
    fill_with_random(new_key, sizeof(new_key));
    memcpy(new_key_enc, new_key, sizeof(new_key_enc));

    if (btran_send(ctx, new_key_enc, sizeof(new_key_enc)) != 0)
        return 1;
    memcpy(ctx->key_hash, new_key, sizeof(new_key));
    return 0;
}

static int let_exchange_key(btran_ctx_t* ctx)
{
    uint8_t* new_key;
    uint32_t new_key_size;

    if (btran_recv(ctx, &new_key, &new_key_size, AUTH_TIMEOUT) != 0)
        return 1;
    if (new_key_size != 32) {
        error("let_exchange_key: unexpected key size %u", new_key_size);
        btran_free(new_key);
        return 1;
    }

    memcpy(ctx->key_hash, new_key, 32);
    btran_free(new_key);
    return 0;
}

static int authenticate(btran_ctx_t* ctx, uint32_t* rand)
{
    uint32_t auth_rand, auth_rand_resp = 0;
    fill_with_random((uint8_t*)&auth_rand, sizeof(auth_rand));

    debug("authenticate: sending auth token: 0x%08x", auth_rand);
    if (send_uint32_t(ctx, auth_rand) != 0)
        return 1;
    if (recv_uint32_t(ctx, &auth_rand_resp, AUTH_TIMEOUT) != 0 ||
        auth_rand_resp != (auth_rand ^ 0xabadcafe)) {
        warning("authenticate: authentication failed, received 0x%08x, "
                "expected 0x%08x",
                auth_rand_resp, auth_rand ^ 0xabadcafe);
        return 1;
    }

    *rand = auth_rand;
    return 0;
}

static int let_authenticate(btran_ctx_t* ctx, uint32_t* rand)
{
    uint32_t auth_rand;
    if (recv_uint32_t(ctx, &auth_rand, AUTH_TIMEOUT))
        return 1;
    debug("let_authenticate: received auth token: 0x%08x", auth_rand);
    if (send_uint32_t(ctx, auth_rand ^ 0xabadcafe) != 0)
        return 1;

    *rand = auth_rand;
    return 0;
}

int btran_connect(btran_ctx_t* ctx, const char* addr, int port)
{
    if (ctx->ftab->connect(ctx, addr, port) != 0)
        return 1;

    uint32_t rand1, rand2;
    if (authenticate(ctx, &rand1) != 0) {
        error("btran_connect: authentication failed");
        goto err;
    }
    if (let_authenticate(ctx, &rand2) != 0) {
        error("btran_connect: server authentication failed");
        goto err;
    }

    ctx->session_token = rand1 ^ rand2;
    if (let_exchange_key(ctx) != 0) {
        error("btran_connect: unable to exchange key");
        goto err;
    }
    return 0;

err:
    btran_disconnect(ctx);
    return 1;
}

int btran_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn)
{
    if (ctx->ftab->accept(ctx, o_conn) != 0)
        return 1;

    memcpy(o_conn->key_hash, ctx->key_hash, sizeof(ctx->key_hash));
    o_conn->ty            = ctx->ty;
    o_conn->session_token = 0;

    uint32_t rand1, rand2;
    if (let_authenticate(o_conn, &rand1) != 0) {
        error("btran_accept: client authentication failed");
        goto err;
    }
    if (authenticate(o_conn, &rand2) != 0) {
        error("btran_accept: authentication failed");
        goto err;
    }

    o_conn->session_token = rand1 ^ rand2;
    if (exchange_key(o_conn) != 0) {
        error("btran_accept: unable to exchange key");
        goto err;
    }
    return 0;

err:
    btran_dispose(o_conn);
    return 1;
}

static int recv_all(btran_ctx_t* ctx, uint8_t* buf, uint32_t size,
                    uint32_t timeout)
{
    uint32_t nreceived = 0;
    while (nreceived != size) {
        uint32_t nread;
        if (ctx->ftab->recv(ctx, buf + nreceived, size - nreceived, &nread,
                            timeout) != 0)
            return 1;
        nreceived += nread;
    }
    return 0;
}

static int recv_uint32_t(btran_ctx_t* ctx, uint32_t* data, uint32_t timeout)
{
    uint8_t* buf;
    uint32_t size;
    if (btran_recv(ctx, &buf, &size, timeout) != 0)
        return 1;

    if (size != 4) {
        error("recv_uint32_t: unexpected message size");
        free(buf);
        return 1;
    }

    *data = htonl(*(uint32_t*)buf);
    free(buf);
    return 0;
}

int btran_recv(btran_ctx_t* ctx, uint8_t** o_buf, uint32_t* o_size,
               uint32_t timeout)
{
    uint8_t nonce[8];
    if (recv_all(ctx, nonce, sizeof(nonce), timeout) != 0)
        return 1;

    uint32_t session_raw;
    if (recv_all(ctx, (uint8_t*)&session_raw, sizeof(session_raw), timeout) !=
        0)
        return 1;
    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 0,
                  (uint8_t*)&session_raw, sizeof(session_raw)) != S20_SUCCESS)
        panic("encryption failed");
    if (ntohl(session_raw) != ctx->session_token) {
        error("invalid session token");
        return 1;
    }

    uint32_t size_netendian;
    if (recv_all(ctx, (uint8_t*)&size_netendian, sizeof(size_netendian),
                 timeout) != 0)
        return 1;
    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 4,
                  (uint8_t*)&size_netendian,
                  sizeof(size_netendian)) != S20_SUCCESS)
        panic("encryption failed");

    uint32_t size = ntohl(size_netendian);
    uint8_t* buf  = btran_malloc(size);
    if (recv_all(ctx, buf, size, timeout) != 0) {
        btran_free(buf);
        return 1;
    }
    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 8, buf, size) !=
        S20_SUCCESS)
        panic("encryption failed");

    *o_buf  = buf;
    *o_size = size;
    return 0;
}

static int send_all(btran_ctx_t* ctx, uint8_t* buf, uint32_t size)
{
    uint32_t nsent = 0;
    while (nsent != size) {
        uint32_t ns;
        if (ctx->ftab->send(ctx, buf + nsent, size - nsent, &ns) != 0)
            return 1;
        nsent += ns;
    }
    return 0;
}

static int send_uint32_t(btran_ctx_t* ctx, uint32_t data)
{
    uint32_t data_netendian = htonl(data);
    if (btran_send(ctx, (uint8_t*)&data_netendian, sizeof(data_netendian)) != 0)
        return 1;
    return 0;
}

int btran_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t size)
{
    uint8_t nonce[8];
    fill_with_random(nonce, sizeof(nonce));
    if (send_all(ctx, nonce, sizeof(nonce)) != 0)
        return 1;

    uint32_t session_token_raw = htonl(ctx->session_token);
    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 0,
                  (uint8_t*)&session_token_raw,
                  sizeof(session_token_raw)) != S20_SUCCESS)
        panic("encryption failed");
    if (send_all(ctx, (uint8_t*)&session_token_raw,
                 sizeof(session_token_raw)) != 0)
        return 1;

    uint32_t size_netendian = htonl(size);
    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 4,
                  (uint8_t*)&size_netendian,
                  sizeof(size_netendian)) != S20_SUCCESS)
        panic("encryption failed");
    if (send_all(ctx, (uint8_t*)&size_netendian, sizeof(size_netendian)) != 0)
        return 1;

    if (s20_crypt(ctx->key_hash, S20_KEYLEN_256, nonce, 8, buf, size) !=
        S20_SUCCESS)
        panic("encryption failed");
    if (send_all(ctx, buf, size) != 0)
        return 1;
    return 0;
}
