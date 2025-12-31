#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#define ROUND_UP(x, a) (((x) + ((a) - 1)) / (a) * (a))

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
Vector page_list; // Vector of PageBlocks
size_t page_list_cap;
// Malloc
void *heap_start;
#ifndef HEAP_SIZE
#define HEAP_SIZE (8 * 1024 * 1024)
#endif
Vector free_list;

typedef struct PageBlock {
    void *ptr;
    size_t size; // multiples of PAGE_SIZE
    size_t offset; // absolute offset w.r.t. 0 (heap start offset)
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

typedef struct FreeBlock {
    size_t page_index; // maps to page_list index
    size_t offset;
    size_t size;
} FreeBlock;



// Sort of like our free list
// Dynamic arrays

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

// Malloc

void *smalloc(size_t size){
    if(size > HEAP_SIZE){
        perror("Requested size exceeds heap size");
        return NULL;
    }

    if(page_list.len == 0){
        printf("page_list.len: %zu\n", page_list.len);
        PageBlock page_block = create_page_block(size, 0);
        push(&page_list, &page_block);
    }

    void *ptr = NULL;
    int ALLOCATED = 0;
    if(size <= PAGE_SIZE){
        // Loop through the free list to find a suitable block
        for(int i = 0; i < free_list.len; i++) {
            // FreeBlock *free_block = (FreeBlock *)get(&free_list, i);
            if(size < ((FreeBlock *)get(&free_list, i))->size){
                // Check if there is enough space in this page or not
                FreeBlock *free_block = (FreeBlock *)get(&free_list, i);
                PageBlock *page_block = get(&page_list, free_block->page_index);

                assert(free_block->offset >= page_block->offset);
                if(page_block->size < free_block->offset - page_block->offset){
                    fprintf(stderr, "Error: Page size is smaller than the available space in the free block\n");
                    exit(1);
                }
                size_t available_size = page_block->size - (free_block->offset - page_block->offset);
                if(available_size >= size) {
                    ptr = (char *)page_block + free_block->offset;
                    free_block->offset += size;
                    free_block->size -= size;
                    ALLOCATED = 1;
                    break;
                }
                /*  If there is available space in the current free block
                **  But there is no available space in the page for that free block
                ** We split this free block into two
                */
                size_t new_offset = page_block->offset + page_block->size;
                PageBlock new_page_block = create_page_block(size, new_offset);
                push(&page_list, &new_page_block);
                size_t new_available_size = free_block->size - new_offset;
                FreeBlock new_free_block = {
                    .offset = new_offset,
                    .size = new_available_size,
                    .page_index = page_list.len - 1
                };
                push(&free_list, &new_free_block);

                free_block->size = available_size;
                ptr = (char *)new_page_block.ptr;
                ALLOCATED = 1;
                break;
            }
        }
        if(!ALLOCATED){
            //TODO: Remove this code block
            void *page_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            FreeBlock new_free_ptr = {page_list.len, 0, size};
            push(&page_list, page_ptr);
            push(&free_list, &new_free_ptr);
            // set ptr
            ptr = page_ptr;
            new_free_ptr.offset = size;
        }
    } else {
        // now we must create a new page
        PageBlock new_page_block = create_page_block(size, sum_page_list_size());
        push(&page_list, &new_page_block);
        ptr = new_page_block.ptr;
        int page_index = page_list.len - 1;
        // now we find the next compatible free block
        FreeBlock *large_free_block = NULL;
        int large_free_block_index = -1;
        for(int i = 0; i < free_list.len; i++){
            FreeBlock *free_block = get(&free_list, i);
            if(free_block->size < size) continue;
            large_free_block = free_block;
            large_free_block_index = i;
            break;
        }
        // now we break this large free block into two
        if(large_free_block){
            size_t page_index = large_free_block->page_index;
            PageBlock *page_block = get(&page_list, page_index);
            assert(page_block->offset + page_block->size >= large_free_block->offset);
            size_t available_space = page_block->offset + page_block->size - large_free_block->offset;
            if (available_space >= size) {
                ptr = page_block->ptr + large_free_block->offset;
                large_free_block->size -= size;
                large_free_block->offset += size;
                ALLOCATED = 1;
            } else {
                // create a new free block
                size_t new_offset = sum_page_list_size();
                PageBlock new_page_block = create_page_block(size, new_offset);
                // we gotta split the large_free_block into two
                push(&page_list, &new_page_block);

                // Create new free block
                assert(large_free_block->size >= available_space);
                FreeBlock new_free_block = {
                    .offset = new_offset,
                    .size = large_free_block->size - available_space,
                    .page_index = page_list.len - 1
                };
                large_free_block->size = available_space;
                push(&free_list, &new_free_block);
                ptr = new_page_block.ptr;
                ALLOCATED = 1;
                // we gotta put the shit at large_free_block_index (yepp... some array shit to do now)
            }
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

void free(void *ptr){
   // this is going to be a pain in the ass
}

void init_allocator(){
    free_list = create_vector(sizeof(FreeBlock));
    FreeBlock init_free_block = {0,0,HEAP_SIZE};
    page_list_cap = HEAP_SIZE / PAGE_SIZE;
    push(&free_list, &init_free_block);
    page_list = create_vector(sizeof(PageBlock));
}

void init(){
    init_page_size();
    if(PAGE_SIZE == 0){
        perror("Page size could not be initialized");
    }
        init_allocator();
}
// Debuggers
void print_free_block(FreeBlock* fb){
    printf("FreeBlock{Offset: %zu, Size: %zu, Page Index: %zu}\n", fb->offset, fb->size, fb->page_index);
}
void print_vec_fb(Vector* v){
    for(size_t i = 0; i < v->len; i++){
        print_free_block((FreeBlock *)((char *)v->data + i*v->elem_size));
    }
    printf("\n");
}

int main(){
    init();
    printf("PAGE SIZE: %zu\n", PAGE_SIZE);

    void* ptr1 = smalloc(PAGE_SIZE/2);
    void* ptr2 = smalloc(PAGE_SIZE/2);
    void* ptr3 = smalloc(PAGE_SIZE+1);
    void* ptr4 = smalloc(2 * PAGE_SIZE + 5);

    print_vec_fb(&free_list);
    printf("ptr1: %p\n", ptr1);
    printf("ptr2: %p\n", ptr2);
    printf("ptr3: %p\n", ptr3);
    printf("ptr4: %p\n", ptr4);
    return 0;
}
