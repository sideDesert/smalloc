#ifndef SMALLOC_H
#define SMALLOC_H

#include <stddef.h>

void init(void);
void *smalloc(size_t size);
void sfree(void *ptr);

// optional debug helpers
void print_block_list(void);
void print_free_list(void);

#endif
