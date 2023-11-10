#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>

void* btran_malloc(size_t size);
void* btran_calloc(size_t size);
void  btran_free(void* buf);

#endif
