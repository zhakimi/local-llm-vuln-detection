#include <stdio.h>
#include <string.h>

static void greet(const char *name) {
    char buffer[32];
    strcpy(buffer, name);
    printf("Hello, %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s NAME\n", argv[0]);
        return 1;
    }
    greet(argv[1]);
    return 0;
}
