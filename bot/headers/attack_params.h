#pragma once

#ifndef ATTACK_PARAMS_H
#define ATTACK_PARAMS_H

#include <arpa/inet.h>
#include <stdint.h>

typedef struct {
    struct sockaddr_in target_addr;  
    uint32_t duration;               
    volatile uint32_t active;        
    uint32_t psize;                  
    uint16_t srcport;
    uint8_t http_method;  // 1=GET, 2=POST, 4=HEAD, can be combined with OR (not str for eff)
    uint32_t base_ip;
    uint8_t cidr;        // 0 =normal else /1 - /32
} attack_params;

typedef struct {
    struct sockaddr_in target_addr; 
    uint32_t duration;               
    volatile uint32_t active;       
    uint32_t psize;                 
    uint16_t srcport;                
    uint16_t gre_proto;             
    uint16_t gport;                 
} gre_attack_params;

#endif // ATTACK_PARAMS_H
