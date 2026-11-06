#include <stdio.h>
#include <string.h>

int main(void) {
    char username[64];
    char greeting[96];
    printf("username: ");
    if (fgets(username, sizeof username, stdin) == NULL) {
        return 1;
    }
    username[strcspn(username, "\n")] = '\0';
    snprintf(greeting, sizeof greeting, "welcome %s", username);
    puts(greeting);
    return 0;
}
