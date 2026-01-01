#include <stdalign.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#define ALIGNMENT alignof(max_align_t)
#define ROUND_UP(x, a) (((x) + ((a) - 1)) / (a) * (a))
#define ALIGN_UP(x) ROUND_UP(x, ALIGNMENT)
#define MAGIC 0xDEADBEEF

typedef struct Vector {
    void *data;
    size_t cap; // this is guaranteed to be a natural number
    size_t len;
    size_t elem_size;
} Vector;

size_t PAGE_SIZE = 0;
void init_page_size(){
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
}
// Malloc
void *heap_start;
#ifndef HEAP_SIZE
#define HEAP_SIZE (8 * 1024 * 1024)
#endif
Vector block_list; // Vector of pointers in memory
Vector free_list; // Vector of size_t (indices to free block list elements)
Vector page_list; // Vector of PageBlocks
size_t page_list_cap; // maximum number of pages

typedef struct PageBlock {
    void *ptr;
    size_t size; // multiples of PAGE_SIZE
    size_t offset; // absolute offset w.r.t. 0 (theoretical heap start offset)
} PageBlock;

PageBlock create_page_block(size_t size, size_t offset) {
    size_t ceilSize = ROUND_UP(size, PAGE_SIZE);

    PageBlock pb = {
        .size = ceilSize,
        .offset = offset,
        .ptr = mmap(NULL, ceilSize,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    };

    if (pb.ptr == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    return pb;  // ← copied to caller
}

typedef struct  AllocHeader {
    size_t page_index; // maps to page_list index
    size_t offset;
    size_t size;
    int is_free;
    uint32_t magic;
} AllocHeader;
#define HDR ALIGN_UP(sizeof(AllocHeader))

Vector create_vector(size_t elem_size){
    Vector v = {NULL, 0, 0, elem_size};
    return v;
}

void push(Vector* v, void* item){
    int IS_INIT = v->data == NULL;
    if(v->cap == v->len){
        v->cap = v->cap + PAGE_SIZE/v->elem_size;
        void *new_ptr = mmap(NULL, v->cap * v->elem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(new_ptr, v->data, v->len * v->elem_size);
        if(!IS_INIT){
            munmap(v->data, v->len * v->elem_size);
        }
        v->data = new_ptr;
    }
    memcpy((char *)v->data + v->len*v->elem_size, item, v->elem_size);
    v->len++;
}

void *get(Vector *v, size_t index){
    if (index >= v->len) {
        perror("Index out of bounds");
        return NULL;
    }
    return (char *)v->data + index * v->elem_size;
}

void pop(Vector* v){
    if(v->len == 0) {
        perror("Vector is empty");
    }
    if(v->len > 0){
        v->len--;
    }
}

void remove_at(Vector *v, size_t i){
    if(i >= v->len){
        fprintf(stderr, "Index %zu out of bounds for vector of length %zu", i, v->len);
        exit(1);
    }
    int last_index = v->len - 1;
    memcpy((char *)v->data + i*v->elem_size, (char *)v->data + last_index*v->elem_size, v->elem_size);
    pop(v);
}

void print_vec_int(Vector* v){
    for(size_t i = 0; i < v->len; i++){
        printf("%d ", *(int *)((char *)v->data + i*v->elem_size));
    }
    printf("\n");
}
size_t sum_page_list_size(){
    size_t new_offset = 0;
    for(int i = 0; i < page_list.len; i++){
        new_offset += ((PageBlock *)get(&page_list, i))->size;
    }
    return new_offset;
}

void init_allocator(void *init_page_ptr){
    block_list = create_vector(sizeof(void *));
    free_list = create_vector(sizeof(size_t));
    AllocHeader init_block = {
        .is_free = 1,
        .magic = MAGIC,
        .offset = 0,
        .page_index = 0,
        .size = HEAP_SIZE,
    };
    AllocHeader *init_block_ptr = (AllocHeader *)init_page_ptr;
    *init_block_ptr = init_block;
    page_list_cap = HEAP_SIZE / PAGE_SIZE;
    push(&block_list, &init_page_ptr);
    size_t free_block_index = 0;
    push(&free_list, &free_block_index);
}

AllocHeader *get_free_block(size_t index){
    size_t free_block_index = *(size_t *)get(&free_list, index);
    void **free_block_ptr = (void **)get(&block_list, free_block_index);
    AllocHeader *free_block = (AllocHeader *)*free_block_ptr;
    printf("free_block: %p\n", (char *)free_block);
    assert(free_block->is_free);
    return free_block;
}

// Malloc
void *smalloc(size_t mem_size){
    size_t size = ALIGN_UP(mem_size);
    if(size > HEAP_SIZE){
        perror("Requested size exceeds heap size");
        return NULL;
    }

    if(page_list.len == 0){
        printf("page_list.len: %zu\n", page_list.len);
        PageBlock page_block = create_page_block(size + sizeof(AllocHeader), 0);
        push(&page_list, &page_block);
        init_allocator(page_block.ptr);
    }

    void *ptr = NULL;
    int ALLOCATED = 0;
        for(int i = 0; i < free_list.len; i++) {
            AllocHeader *free_block = get_free_block(i);
            if(free_block->size >= size){
                // Check if there is enough space in this page or not
                PageBlock *page_block = get(&page_list, free_block->page_index);
                assert(free_block->offset >= page_block->offset);
                if(page_block->size < free_block->offset - page_block->offset){
                    fprintf(stderr, "Error: Page size is smaller than the available space in the free block\n");
                    exit(1);
                }
                size_t available_size = page_block->size - (free_block->offset - page_block->offset);
                if(available_size >= size + HDR) {
                    void *rawptr = (void *)free_block;
                    ptr = rawptr + HDR;
                    // Create new free block
                    AllocHeader new_block = {
                        .offset = free_block->offset + size + HDR,
                        .size = free_block->size - size - HDR,
                        .page_index = free_block->page_index,
                        .magic = MAGIC,
                        .is_free = 1
                    };
                    free_block->size = size;
                    free_block->is_free = 0;
                    remove_at(&free_list, i);
                    // Set memory ptr = new_bo
                    void *new_free_ptr = (char *)rawptr + HDR + size;
                    *((AllocHeader *)new_free_ptr) = new_block;
                    push(&block_list, &new_free_ptr);
                    size_t new_free_block_index = block_list.len - 1;
                    push(&free_list, &new_free_block_index);
                    // Add new block
                    // push(&block_list, &rawptr);

                    ALLOCATED = 1;
                    break;
                }
                /*  If there is available space in the current free block
                **  But there is no available space in the page for that free block
                ** We split this free block into two
                */
                size_t new_offset = page_block->offset + page_block->size;
                PageBlock new_page_block = create_page_block(size + 2 * HDR, new_offset);
                push(&page_list, &new_page_block);

                size_t new_available_size = free_block->size - new_offset;
                // We gotta split this again into two
                // One is used - size + sizeof(AllocHeader)
                AllocHeader new_use_block_header = {
                    .offset = new_offset,
                    .size = size,
                    .page_index = page_list.len - 1,
                    .is_free = 0,
                    .magic = MAGIC,
                };
                // other is unused - new_available_size - (size + sizeof(AllocHeader)) w/ offset = new_offset + size + sizeof(AllocHeader)
                AllocHeader new_free_block_header = {
                    .offset = new_offset + size + HDR,
                    .size = new_available_size - (size + HDR),
                    .page_index = page_list.len - 1,
                    .is_free = 1,
                    .magic = MAGIC,
                };
                AllocHeader *allocated_block_ptr = (AllocHeader *)new_page_block.ptr;
                *allocated_block_ptr = new_use_block_header;
                // Add the free block header to where it should be
                void *free_block_ptr = (char *)allocated_block_ptr + HDR + size;
                memcpy(free_block_ptr, &new_free_block_header, sizeof(AllocHeader));
                push(&block_list, &allocated_block_ptr);
                push(&block_list, &free_block_ptr);
                size_t free_block_index = block_list.len - 1;
                push(&free_list, &free_block_index);

                void *rptr = (void *)new_page_block.ptr;
                ptr = (char *)rptr + HDR;
                // Push new free block to free list
                size_t block_index = block_list.len - 1;

                free_block->size = available_size;
                ALLOCATED = 1;
                break;
            }
        }

    // Check if end is within page
    if(ALLOCATED){
      return ptr;
    } else {
       fprintf(stderr, "Error: Out of memory\n");
       abort();
    }
}

size_t find_block_index(void *target_ptr){
   for(size_t i = 0; i < block_list.len; i++) {
       void **block_ptr = (void **)get(&block_list, i);
       AllocHeader *header = (AllocHeader *)*block_ptr;

       // Check if this block's user data pointer matches
       void *block_user_ptr = (char *)header + HDR;
       if(block_user_ptr == target_ptr)
           return i;
   }
   fprintf(stderr, "Error: Pointer not found in block list\n");
   abort();
}

void sfree(void *ptr){
   if(ptr == NULL) return;
   AllocHeader *header_ptr = (AllocHeader *)((char *)ptr - HDR);
   if(header_ptr->magic != MAGIC){
       fprintf(stderr, "Error: Invalid memory or corrupted header\n");
       abort();
   }
   if(header_ptr->is_free) {
       fprintf(stderr, "Error: Double free detected\n");
       abort();
   }

   header_ptr->is_free = 1;
   size_t index = find_block_index(ptr);
   push(&free_list, &index);
}


void init(){
    init_page_size();
    page_list = create_vector(sizeof(PageBlock));
    if(PAGE_SIZE == 0){
        perror("Page size could not be initialized");
    }
}
// Debuggers
void print_free_block(AllocHeader* fb){
    printf("FreeBlock{Offset: %zu, Size: %zu, Page Index: %zu}\n", fb->offset, fb->size, fb->page_index);
}
void print_vec_fb(Vector* v){
    for(size_t i = 0; i < v->len; i++){
        print_free_block((AllocHeader *)((char *)v->data + i*v->elem_size));
    }
    printf("\n");
}

void visualize_heap(Vector *free_list) {
    const int WIDTH = 100;
    char bar[WIDTH + 1];

    // start fully used
    for (int i = 0; i < WIDTH; i++) bar[i] = '#';
    bar[WIDTH] = '\0';

    // mark free blocks
    for (int i = 0; i < free_list->len; i++) {
        AllocHeader *fb = get(free_list, i);

        size_t start = fb->offset;
        size_t end   = fb->offset + fb->size;

        int s = (int)((double)start / HEAP_SIZE * WIDTH);
        int e = (int)((double)end   / HEAP_SIZE * WIDTH);

        if (s < 0) s = 0;
        if (e > WIDTH) e = WIDTH;

        for (int j = s; j < e; j++) {
            bar[j] = '.';
        }
    }

    printf("HEAP [# = used, . = free]\n");
    printf("|%s|\n", bar);
}
int main(){
    init();
    printf("PAGE SIZE: %zu\n", PAGE_SIZE);

    void* ptr1 = smalloc(2 * PAGE_SIZE);
    void* ptr2 = smalloc(PAGE_SIZE/2);
    void* ptr3 = smalloc(PAGE_SIZE+1);
    void* ptr4 = smalloc(2 * PAGE_SIZE + 5);

    print_vec_fb(&free_list);
    printf("ptr1: %p\n", ptr1);
    printf("ptr2: %p\n", ptr2);
    printf("ptr3: %p\n", ptr3);
    printf("ptr4: %p\n", ptr4);

    for(int i = 0; i <= 100; i++){
        size_t rand_size = (size_t)(arc4random_uniform(PAGE_SIZE - 1) + 1);
        printf("%d: Allocating %zu bytes\n",i, rand_size);
        smalloc(rand_size);
        // smalloc(rand);
    }

    return 0;
}
