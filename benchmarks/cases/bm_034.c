#include <stdio.h>

int main(void) {
    char username[64];
    printf("username: ");
    gets(username);
    printf("welcome %s\n", username);
    return 0;
}
