#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char cmd[512];
    if (argc < 2) {
        return 1;
    }
    snprintf(cmd, sizeof cmd, "tar -czf /backups/archive.tgz %s", argv[1]);
    return system(cmd);
}
