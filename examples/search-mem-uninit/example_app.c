#include <stdio.h>

volatile int example_global = 1;

void*
current_return_addr(void) {
    return __builtin_return_address(0);
}

int
main(void) {
    printf("example_global=%d\n", example_global);
    printf("snapshot_addr=%p\n", current_return_addr());
    example_global += 1;
    return 0;
}

