#include "smalloc.h"
#include "vector.h"

#include <stdalign.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#define ALIGNMENT alignof(max_align_t)
#define ROUND_UP(x, a) (((x) + ((a) - 1)) / (a) * (a))
#define ALIGN_UP(x) ROUND_UP(x, ALIGNMENT)
#define MAGIC 0xDEADBEEF

#ifndef HEAP_SIZE
#define HEAP_SIZE (8 * 1024 * 1024)
#endif

typedef struct PageBlock {
    void *ptr;
    size_t size;
    size_t offset;
} PageBlock;

typedef struct AllocHeader {
    size_t page_index;
    size_t offset;
    size_t size;
    int is_free;
    unsigned int magic;
} AllocHeader;

#define HDR ALIGN_UP(sizeof(AllocHeader))

/* ===== Global allocator state (OWNED HERE) ===== */
size_t PAGE_SIZE = 0;

Vector block_list;
Vector free_list;
Vector page_list;

/* =============================================== */

static void init_page_size(void) {
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if (PAGE_SIZE == 0) {
        perror("sysconf");
        exit(1);
    }
}

static PageBlock create_page_block(size_t size, size_t offset) {
    size_t rounded = ROUND_UP(size, PAGE_SIZE);

    void *ptr = mmap(NULL,
                     rounded,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    return (PageBlock){
        .ptr = ptr,
        .size = rounded,
        .offset = offset
    };
}

static void init_allocator(void *page_ptr) {
    block_list = create_vector(sizeof(void *));
    free_list  = create_vector(sizeof(size_t));

    AllocHeader *h = (AllocHeader *)page_ptr;
    *h = (AllocHeader){
        .page_index = 0,
        .offset = 0,
        .size = HEAP_SIZE,
        .is_free = 1,
        .magic = MAGIC
    };

    push(&block_list, &page_ptr);

    size_t idx = 0;
    push(&free_list, &idx);
}

static AllocHeader *get_free_block(size_t i) {
    size_t block_idx = *(size_t *)get(&free_list, i);
    void **slot = (void **)get(&block_list, block_idx);
    AllocHeader *h = (AllocHeader *)*slot;
    assert(h->is_free);
    return h;
}

/* ================= PUBLIC API ================= */

void init(void) {
    init_page_size();
    page_list = create_vector(sizeof(PageBlock));
}

void *smalloc(size_t size) {
    size = ALIGN_UP(size);

    if (page_list.len == 0) {
        PageBlock pb = create_page_block(size + HDR, 0);
        push(&page_list, &pb);
        init_allocator(pb.ptr);
    }

    for (size_t i = 0; i < free_list.len; i++) {
        AllocHeader *fb = get_free_block(i);
        if (fb->size < size + HDR)
            continue;

        void *raw = (void *)fb;
        fb->is_free = 0;

        remove_at(&free_list, i);

        size_t remaining = fb->size - size - HDR;
        fb->size = size;

        if (remaining > 0) {
            AllocHeader *nh = (AllocHeader *)((char *)raw + HDR + size);
            *nh = (AllocHeader){
                .page_index = fb->page_index,
                .offset = fb->offset + HDR + size,
                .size = remaining,
                .is_free = 1,
                .magic = MAGIC
            };

            push(&block_list, &nh);
            size_t idx = block_list.len - 1;
            push(&free_list, &idx);
        }

        return (char *)raw + HDR;
    }

    fprintf(stderr, "smalloc: out of memory\n");
    abort();
}

void sfree(void *ptr) {
    if (!ptr) return;

    AllocHeader *h = (AllocHeader *)((char *)ptr - HDR);
    if (h->magic != MAGIC || h->is_free) {
        fprintf(stderr, "invalid free\n");
        abort();
    }

    h->is_free = 1;

    for (size_t i = 0; i < block_list.len; i++) {
        void **slot = (void **)get(&block_list, i);
        if (*slot == h) {
            push(&free_list, &i);
            return;
        }
    }

    abort();
}

/* ================= DEBUG ================= */

void print_block_list(void) {
    printf("BLOCK LIST\n");
    for (size_t i = 0; i < block_list.len; i++) {
        void **slot = (void **)get(&block_list, i);
        AllocHeader *h = (AllocHeader *)*slot;
        printf("[%zu] off=%zu size=%zu %s\n",
               i,
               h->offset,
               h->size,
               h->is_free ? "FREE" : "USED");
    }
}

void print_free_list(void) {
    printf("FREE LIST\n");
    for (size_t i = 0; i < free_list.len; i++) {
        size_t idx = *(size_t *)get(&free_list, i);
        printf("[%zu] block_idx=%zu\n", i, idx);
    }
}
