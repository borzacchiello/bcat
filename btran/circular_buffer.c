#include <string.h>
#include <errno.h>

#include "circular_buffer.h"
#include "alloc.h"
#include "log.h"

#define min(a, b) ((a) < (b) ? (a) : (b))

int cb_init(circular_buffer_t* cb, uint32_t capacity)
{
    cb->buffer     = btran_malloc(capacity);
    cb->buffer_end = (uint8_t*)cb->buffer + capacity;
    cb->capacity   = capacity;
    cb->count      = 0;
    cb->head       = cb->buffer;
    cb->tail       = cb->buffer;

    if (sem_init(&cb->s, 0, 1) != 0) {
        int r = errno;
        error("cb_init(): unable to initialize semaphore [%s]", strerror(r));
        btran_free(cb->buffer);
        cb->buffer = NULL;
        return r;
    }
    return 0;
}

void cb_free(circular_buffer_t* cb)
{
    sem_destroy(&cb->s);
    btran_free(cb->buffer);
    memset(cb, 0, sizeof(circular_buffer_t));
}

int64_t cb_write(circular_buffer_t* cb, const uint8_t* data, uint32_t data_size)
{
    if (sem_wait(&cb->s) != 0)
        panic("cb_write(): unable to wait on semaphore [%s]", strerror(errno));

    if (cb->count + data_size > cb->capacity) {
        // not enough space in the buffer
        error("cb_write(): not enough space in the buffer");
        if (sem_post(&cb->s) != 0)
            panic("cb_write(): unable to release semaphore [%s]",
                  strerror(errno));
        return -1;
    }

    if (cb->head + data_size <= cb->buffer_end) {
        // no need to split
        memcpy(cb->head, data, data_size);
        cb->head = (uint8_t*)cb->head + data_size;
        if (cb->head == cb->buffer_end)
            cb->head = cb->buffer;
    } else {
        // split data
        size_t first_piece_size  = cb->buffer_end - cb->head;
        size_t second_piece_size = data_size - first_piece_size;

        memcpy(cb->head, data, first_piece_size);
        memcpy(cb->buffer, data + first_piece_size, second_piece_size);

        cb->head = cb->buffer + second_piece_size;
    }
    cb->count += data_size;

    if (sem_post(&cb->s) != 0)
        panic("cb_write(): unable to release semaphore [%s]", strerror(errno));
    return (int64_t)data_size;
}

int64_t cb_read(circular_buffer_t* cb, uint8_t* data, uint32_t data_size)
{
    if (sem_wait(&cb->s) != 0)
        panic("cb_read(): unable to wait on semaphore [%s]", strerror(errno));

    uint32_t toread = min(data_size, cb->count);
    if (toread == 0) {
        if (sem_post(&cb->s) != 0)
            panic("cb_read(): unable to release semaphore [%s]",
                  strerror(errno));
        return 0;
    }

    if (cb->tail + toread <= cb->buffer_end) {
        // no need to split
        memcpy(data, cb->tail, toread);
        cb->tail = (uint8_t*)cb->tail + toread;
        if (cb->tail == cb->buffer_end)
            cb->tail = cb->buffer;
    } else {
        // split data
        size_t first_piece_size  = cb->buffer_end - cb->tail;
        size_t second_piece_size = toread - first_piece_size;

        memcpy(data, cb->tail, first_piece_size);
        memcpy(data + first_piece_size, cb->buffer, second_piece_size);

        cb->tail = cb->buffer + second_piece_size;
    }
    cb->count -= toread;

    if (sem_post(&cb->s) != 0)
        panic("cb_read(): unable to release semaphore [%s]", strerror(errno));
    return (int64_t)toread;
}

void cb_empty(circular_buffer_t* cb)
{
    if (sem_wait(&cb->s) != 0)
        panic("cb_read(): unable to wait on semaphore [%s]", strerror(errno));

    cb->count = 0;
    cb->head  = cb->buffer;
    cb->tail  = cb->buffer;

    if (sem_post(&cb->s) != 0)
        panic("cb_read(): unable to release semaphore [%s]", strerror(errno));
}
