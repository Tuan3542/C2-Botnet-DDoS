#pragma once

#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>

void daemonize(int argc, char **argv);
void overwrite_argv(int argc, char** argv);
void* rename_process(void* arg);
int startup_persist(char *exec);
void cleanup_startup();

#endif // DAEMON_H
