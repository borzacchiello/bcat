// based on https://gist.github.com/ryankurte/61f95dc71133561ed055ff62b33585f8

#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>

typedef struct {
    size_t head;
    size_t tail;
    size_t size;
    void** data;
} queue_t;

queue_t* queue_init(size_t size);
void     queue_destroy(queue_t* queue, void (*free_func)(void*));

void* queue_read(queue_t* queue);
int   queue_write(queue_t* queue, void* handle);

#endif
