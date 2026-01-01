#include "vector.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/*
 * PAGE_SIZE is owned by smalloc.c.
 * vector.c only *uses* it.
 */
extern size_t PAGE_SIZE;

Vector create_vector(size_t elem_size) {
    Vector v = { NULL, 0, 0, elem_size };
    return v;
}

void push(Vector *v, void *item) {
    if (v->cap == v->len) {
        size_t new_cap = v->cap + PAGE_SIZE / v->elem_size;
        void *new_data = mmap(NULL,
                              new_cap * v->elem_size,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1, 0);

        if (new_data == MAP_FAILED) {
            perror("mmap");
            _exit(1);
        }

        if (v->data) {
            memcpy(new_data, v->data, v->len * v->elem_size);
            munmap(v->data, v->cap * v->elem_size);
        }

        v->data = new_data;
        v->cap = new_cap;
    }

    memcpy((char *)v->data + v->len * v->elem_size,
           item,
           v->elem_size);
    v->len++;
}

void *get(Vector *v, size_t index) {
    if (index >= v->len) {
        fprintf(stderr, "Vector index out of bounds\n");
        return NULL;
    }
    return (char *)v->data + index * v->elem_size;
}

void pop(Vector *v) {
    if (v->len > 0)
        v->len--;
}

void remove_at(Vector *v, size_t index) {
    if (index >= v->len) {
        fprintf(stderr, "remove_at: out of bounds\n");
        _exit(1);
    }

    size_t last = v->len - 1;
    memcpy((char *)v->data + index * v->elem_size,
           (char *)v->data + last * v->elem_size,
           v->elem_size);
    pop(v);
}
