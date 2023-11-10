#include "alloc.h"
#include "log.h"

#include <string.h>

void* btran_malloc(size_t size)
{
    void* r = malloc(size);
    if (!r)
        panic("btran_malloc failed");
    return r;
}

void* btran_calloc(size_t size)
{
    void* r = malloc(size);
    memset(r, 0, size);
    return r;
}

void btran_free(void* buf) { free(buf); }
