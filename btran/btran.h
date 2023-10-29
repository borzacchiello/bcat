#ifndef BTRAN_H
#define BTRAN_H

#include <stdint.h>
#include <stdlib.h>

typedef enum btran_backend_t {
    BTRAN_TCP  = 1,
    BTRAN_UDP  = 2,
    BTRAN_ICMP = 3,
} btran_backend_t;

struct btran_ctx_t;
typedef struct btran_ftab_t {
    int  (*dispose)(struct btran_ctx_t* ctx);
    void (*disconnect)(struct btran_ctx_t* ctx);

    int (*listen)(struct btran_ctx_t* ctx, const char* addr, int port);
    int (*connect)(struct btran_ctx_t* ctx, const char* addr, int port);
    int (*accept)(struct btran_ctx_t* ctx, struct btran_ctx_t* o_conn);
    int (*recv)(struct btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                uint32_t* nread, uint32_t timeout);
    int (*send)(struct btran_ctx_t* ctx, uint8_t* buf, uint32_t buf_size,
                uint32_t* nsent);
} btran_ftab_t;

typedef struct btran_ctx_t {
    void*               backendptr;
    const btran_ftab_t* ftab;

    uint8_t         key_hash[32];
    uint32_t        session_token;
    btran_backend_t ty;
} btran_ctx_t;

int  btran_init(btran_ctx_t* ctx, btran_backend_t type, const char* key);
void btran_dispose(btran_ctx_t* ctx);
void btran_disconnect(btran_ctx_t* ctx);

int btran_listen(btran_ctx_t* ctx, const char* addr, int port);
int btran_connect(btran_ctx_t* ctx, const char* addr, int port);
int btran_accept(btran_ctx_t* ctx, btran_ctx_t* o_conn);
int btran_recv(btran_ctx_t* ctx, uint8_t** o_buf, uint32_t* o_size,
               uint32_t timeout);
int btran_send(btran_ctx_t* ctx, uint8_t* buf, uint32_t size);

#endif
