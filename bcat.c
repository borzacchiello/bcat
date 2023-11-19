#include <sys/select.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include "btran/btran.h"

static struct option long_options[] = {
    {"listen", no_argument, 0, 'l'},
    {"protocol", required_argument, 0, 'P'},
    {"key", required_argument, 0, 'K'},
    {"keep", no_argument, 0, 'k'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0} // Null termination required
};

static const char* key  = NULL;
static int         keep = 0;

static void usage(const char* pname)
{
    fprintf(stderr,
            "USAGE: %s [-l] [-P <protocol>] [-K <key>] [-h] <addr> <port>\n"
            "\n"
            "    -h: print help\n"
            "    -l: listen mode\n"
            "    -K: key, required if not in listen mode\n"
            "    -P: backend protocol type [tcp, udp, icmp]\n"
            "    -k: keep the connection alive\n",
            pname);
    exit(0);
}

static btran_backend_t parse_backend_string(const char* name)
{
    if (strcmp(name, "tcp") == 0)
        return BTRAN_TCP;
    if (strcmp(name, "udp") == 0)
        return BTRAN_UDP;
    if (strcmp(name, "icmp") == 0)
        return BTRAN_ICMP;
    return BTRAN_INVALID;
}

static char nibble_to_hex(uint8_t v)
{
    v &= 0xf;
    if (v < 10)
        return '0' + v;
    return 'a' + (v - 10);
}

static int gen_key(char key[33])
{
    uint8_t tmp[16];
    if (getentropy(tmp, sizeof(tmp)) != 0) {
        fprintf(stderr, "[!] unable to generate key\n");
        return 1;
    }

    for (size_t i = 0; i < sizeof(tmp); ++i) {
        key[i * 2]     = nibble_to_hex(tmp[i] & 0xf);
        key[i * 2 + 1] = nibble_to_hex((tmp[i] >> 4) & 0xf);
    }
    key[32] = 0;
    return 0;
}

static _Atomic int thread_completed = 0;
static void*       print_from_network_loop(void* _ctx)
{
    btran_ctx_t* ctx = (btran_ctx_t*)_ctx;
    while (1) {
        uint8_t* buf;
        uint32_t size;
        if (btran_recv(ctx, &buf, &size, 0) != 0)
            break;

        size_t nwrote = 0;
        while (nwrote != size)
            nwrote += fwrite(buf + nwrote, 1, size - nwrote, stdout);
        free(buf);
    }

    thread_completed = 1;
    return NULL;
}

void listen_loop(const char* addr, int port, btran_backend_t bty)
{
    static uint8_t tmp[1024 * 10];
    char           keybuf[33];

    if (key == NULL) {
        if (gen_key(keybuf) != 0)
            return;
        fprintf(stderr, "[+] key: %s\n", keybuf);
        key = keybuf;
    }

    btran_ctx_t ctx;
    if (btran_init(&ctx, bty, key) != 0) {
        fprintf(stderr, "[!] btran_init failed\n");
        return;
    }

    if (btran_listen(&ctx, addr, port) != 0) {
        fprintf(stderr, "[!] btran_listen failed\n");
        btran_dispose(&ctx);
        return;
    }
    fprintf(stderr, "[+] listening on %s:%d\n", addr, port);

    while (1) {
        btran_ctx_t client;
        if (btran_accept(&ctx, &client) != 0) {
            fprintf(stderr, "[!] btran_accept failed\n");
            continue;
        }
        fprintf(stderr, "[+] client connected\n");

        pthread_t t;
        pthread_create(&t, NULL, &print_from_network_loop, &client);
        while (1) {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(0, &set);
            struct timeval wait = {.tv_sec = 1, .tv_usec = 0};
            select(0 + 1, &set, NULL, NULL, &wait);

            if (FD_ISSET(0, &set)) {
                ssize_t n = read(0, tmp, sizeof(tmp));
                if (n <= 0)
                    break;
                if (btran_send(&client, tmp, n) != 0)
                    break;
            }

            if (thread_completed)
                // thread does not exist, exiting
                break;
        }

        btran_disconnect(&client);
        pthread_join(t, NULL);
        btran_dispose(&client);
        thread_completed = 0;
        fprintf(stderr, "[+] client disconnected\n");

        if (!keep)
            break;
    }
    btran_dispose(&ctx);
}

void connect_loop(const char* addr, int port, btran_backend_t bty)
{
    static uint8_t tmp[1024 * 10];
    thread_completed = 0;

    btran_ctx_t ctx;
    if (btran_init(&ctx, bty, key) != 0) {
        fprintf(stderr, "[!] btran_init failed\n");
        return;
    }

    if (btran_connect(&ctx, addr, port) != 0) {
        fprintf(stderr, "[!] connect failed\n");
        btran_dispose(&ctx);
        return;
    }
    fprintf(stderr, "[+] connected to %s:%d\n", addr, port);

    pthread_t t;
    pthread_create(&t, NULL, &print_from_network_loop, &ctx);
    while (1) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(0, &set);
        struct timeval wait = {.tv_sec = 1, .tv_usec = 0};
        select(0 + 1, &set, NULL, NULL, &wait);

        if (FD_ISSET(0, &set)) {
            ssize_t n = read(0, tmp, sizeof(tmp));
            if (n <= 0)
                break;
            if (btran_send(&ctx, tmp, n) != 0)
                break;
        }

        if (thread_completed)
            // thread does not exist, exiting
            break;
    }

    btran_disconnect(&ctx);
    pthread_join(t, NULL);
    btran_dispose(&ctx);
    fprintf(stderr, "[+] disconnected\n");
}

int main(int argc, char* const* argv)
{
    int             listen_mode = 0;
    btran_backend_t backend_ty  = BTRAN_TCP;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "lK:P:kh", long_options,
                              &option_index)) != -1) {
        switch (opt) {
            case 'l':
                listen_mode = 1;
                break;
            case 'P':
                backend_ty = parse_backend_string(optarg);
                if (backend_ty == BTRAN_INVALID) {
                    fprintf(stderr, "[!] invalid backend \"%s\"\n", optarg);
                    usage(argv[0]);
                }
                break;
            case 'K':
                key = optarg;
                break;
            case 'k':
                keep = 1;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                fprintf(stderr, "[!] invalid option\n");
                usage(argv[0]);
                break;
        }
    }

    const char* addr = NULL;
    int         port = 0;
    for (int i = optind; i < argc; i++) {
        if (i == optind)
            addr = argv[i];
        else if (i == optind + 1)
            port = atoi(argv[i]);
        else
            break;
    }
    if (addr == NULL) {
        fprintf(stderr, "[!] address not provided\n");
        usage(argv[0]);
    }
    if (port == 0) {
        fprintf(stderr, "[!] invalid or missing port\n");
        usage(argv[0]);
    }
    if (!listen_mode && key == NULL) {
        fprintf(stderr, "[!] key required in client mode\n");
        usage(argv[0]);
    }

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    if (listen_mode)
        listen_loop(addr, port, backend_ty);
    else {
        while (1) {
            connect_loop(addr, port, backend_ty);
            if (!keep)
                break;
            sleep(5);
        }
    }
    return 0;
}
