#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "btran/btran.h"

int main(int argc, char const* argv[])
{
    int listen = 0;
    if (argc > 1 && strcmp(argv[1], "-l") == 0)
        listen = 1;

    btran_ctx_t ctx;
    btran_init(&ctx, BTRAN_UDP, "ken is indeed the best!!!");
    if (listen) {
        if (btran_listen(&ctx, "127.0.0.1", 1337) != 0) {
            printf("[!] listen failed\n");
            btran_dispose(&ctx);
            return 1;
        }

        while (1) {
            btran_ctx_t client;
            if (btran_accept(&ctx, &client) != 0) {
                printf("[!] accept failed\n");
                break;
            }

            uint8_t* buf;
            uint32_t buf_size;
            if (btran_recv(&client, &buf, &buf_size, 0) != 0) {
                printf("[!] unable to receive\n");
                btran_dispose(&client);
                continue;
            }
            printf("[+] msg from client: %.*s\n", buf_size, (const char*)buf);

            if (btran_send(&client, buf, buf_size) != 0)
                printf("[!] unable to send echo\n");
            btran_dispose(&client);
            free(buf);
        }
        btran_dispose(&ctx);
        return 1;
    } else {
        if (btran_connect(&ctx, "127.0.0.1", 1337) != 0) {
            printf("[!] connect failed\n");
            btran_dispose(&ctx);
            return 1;
        }

        char msg[] = "hey!";
        if (btran_send(&ctx, (uint8_t*)msg, sizeof(msg)) != 0) {
            printf("[!] unable to send msg\n");
            btran_dispose(&ctx);
            return 1;
        }

        uint8_t* buf;
        uint32_t buf_size;
        if (btran_recv(&ctx, &buf, &buf_size, 0) != 0) {
            printf("[!] unable to receive\n");
            btran_dispose(&ctx);
            return 1;
        }
        printf("[+] msg from server: %.*s\n", buf_size, (const char*)buf);
        free(buf);
        btran_dispose(&ctx);
    }
    return 0;
}
