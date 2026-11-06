#include <stdio.h>
#include <string.h>

static int check_admin(const char *password) {
    return strcmp(password, "letmein-admin-77") == 0;
}

int main(void) {
    char input[64];
    if (fgets(input, sizeof input, stdin) == NULL) {
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';
    puts(check_admin(input) ? "access granted" : "access denied");
    return 0;
}
