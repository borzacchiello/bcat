#include "queue.h"
#include "alloc.h"

queue_t* queue_init(size_t size)
{
    queue_t* q = btran_malloc(sizeof(queue_t));

    q->head = 0;
    q->tail = 0;
    q->size = size;
    q->data = btran_malloc(sizeof(void*) * size);
    return q;
}

void queue_destroy(queue_t* queue, void (*free_func)(void*))
{
    if (free_func) {
        size_t i = queue->tail;
        while (i != queue->head) {
            free_func(queue->data[i]);
            i = (i + 1) % queue->size;
        }
    }
    btran_free(queue->data);
    btran_free(queue);
}

void* queue_read(queue_t* queue)
{
    if (queue->tail == queue->head)
        return NULL;

    void* handle             = queue->data[queue->tail];
    queue->data[queue->tail] = NULL;
    queue->tail              = (queue->tail + 1) % queue->size;
    return handle;
}

int queue_write(queue_t* queue, void* handle)
{
    if (((queue->head + 1) % queue->size) == queue->tail)
        return -1;

    queue->data[queue->head] = handle;
    queue->head              = (queue->head + 1) % queue->size;
    return 0;
}
