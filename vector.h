#ifndef VECTOR_H
#define VECTOR_H

#include <stddef.h>

typedef struct Vector {
    void *data;
    size_t cap;
    size_t len;
    size_t elem_size;
} Vector;

Vector create_vector(size_t elem_size);
void push(Vector *v, void *item);
void *get(Vector *v, size_t index);
void pop(Vector *v);
void remove_at(Vector *v, size_t index);

#endif
