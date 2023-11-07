#ifndef CIRCULAR_H
#define CIRCULAR_H

#include <semaphore.h>
#include <stdint.h>

typedef struct circular_buffer_t {
    void*    buffer;     // data buffer
    void*    buffer_end; // end of data buffer
    uint32_t capacity;   // maximum number of bytes in the buffer
    uint32_t count;      // number of bytes in the buffer
    void*    head;       // pointer to head
    void*    tail;       // pointer to tail

    sem_t s;
} circular_buffer_t;

int  cb_init(circular_buffer_t* cb, uint32_t capacity);
void cb_free(circular_buffer_t* cb);

int64_t cb_write(circular_buffer_t* cb, const uint8_t* data,
                 uint32_t data_size);
int64_t cb_read(circular_buffer_t* cb, uint8_t* data, uint32_t data_size);
void    cb_empty(circular_buffer_t* cb);

#endif
