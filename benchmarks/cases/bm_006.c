#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        char *const args[] = {"/usr/bin/tar", "-czf", "/backups/archive.tgz", "--", argv[1], NULL};
        execv(args[0], args);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
