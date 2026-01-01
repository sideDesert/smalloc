#include "smalloc.h"
#include <stdio.h>
#include <unistd.h>

int main(void) {
    init();

    void *a = smalloc(4096);
    void *b = smalloc(128);
    void *c = smalloc(2048);

    print_block_list();
    print_free_list();

    sfree(a);
    sfree(b);
    sfree(c);

    print_block_list();
    print_free_list();

    return 0;
}
