#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include "firewall.skel.h"

#define CONFIG_FILE "firewall.conf"
#define LOG_FILE "firewall.log"
#define STATUS_FILE "firewall.status"
#define MAX_PORTS 65536
#define MAX_LINE 1024

struct event {
    __u16 dest_port;
    __u16 src_port;
    __u8 protocol;
    char reason[32];
};

struct config {
    int strict_mode;
    int allow_dns;
    int allow_icmp;
    char interface[16];
    int default_ports[64];
    int default_ports_count;
    int custom_ports[MAX_PORTS];
    int custom_ports_count;
};

static struct firewall_bpf *skel = NULL;
static int ifindex = -1;
static volatile int running = 1;

static int parse_config(struct config *cfg) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        f = fopen(CONFIG_FILE, "w");
        if (f) {
            fprintf(f, "[SETTINGS]\n");
            fprintf(f, "strict_mode=1\n");
            fprintf(f, "allow_dns=1\n");
            fprintf(f, "allow_icmp=0\n");
            fprintf(f, "interface=lo\n");
            fprintf(f, "\n[PORTS]\n");
            fprintf(f, "default_ports=22,53,80,443,3000\n");
            fprintf(f, "custom_ports=\n");
            fclose(f);
            f = fopen(CONFIG_FILE, "r");
        }
    }
    
    if (!f) return -1;
    
    cfg->strict_mode = 1;
    cfg->allow_dns = 1;
    cfg->allow_icmp = 0;
    strcpy(cfg->interface, "lo");
    cfg->default_ports_count = 0;
    cfg->custom_ports_count = 0;
    
    char line[MAX_LINE];
    char section[64] = "";
    
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\0' || *p == '#') continue;
        
        p[strcspn(p, "\n\r")] = 0;
        
        if (p[0] == '[' && p[strlen(p)-1] == ']') {
            strncpy(section, p + 1, sizeof(section) - 1);
            section[strlen(section) - 1] = '\0';
        } else if (strcmp(section, "SETTINGS") == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                *eq++ = '\0';
                if (strcmp(p, "strict_mode") == 0) {
                    cfg->strict_mode = atoi(eq);
                } else if (strcmp(p, "allow_dns") == 0) {
                    cfg->allow_dns = atoi(eq);
                } else if (strcmp(p, "allow_icmp") == 0) {
                    cfg->allow_icmp = atoi(eq);
                } else if (strcmp(p, "interface") == 0) {
                    strncpy(cfg->interface, eq, sizeof(cfg->interface) - 1);
                }
            }
        } else if (strcmp(section, "PORTS") == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                *eq++ = '\0';
                if (strcmp(p, "default_ports") == 0) {
                    char *token = strtok(eq, ",");
                    while (token && cfg->default_ports_count < 64) {
                        cfg->default_ports[cfg->default_ports_count++] = atoi(token);
                        token = strtok(NULL, ",");
                    }
                } else if (strcmp(p, "custom_ports") == 0) {
                    char *token = strtok(eq, ",");
                    while (token && cfg->custom_ports_count < MAX_PORTS) {
                        cfg->custom_ports[cfg->custom_ports_count++] = atoi(token);
                        token = strtok(NULL, ",");
                    }
                }
            }
        }
    }
    
    fclose(f);
    return 0;
}

static void write_config(struct config *cfg) {
    FILE *f = fopen(CONFIG_FILE, "w");
    if (!f) return;
    
    fprintf(f, "[SETTINGS]\n");
    fprintf(f, "strict_mode=%d\n", cfg->strict_mode);
    fprintf(f, "allow_dns=%d\n", cfg->allow_dns);
    fprintf(f, "allow_icmp=%d\n", cfg->allow_icmp);
    fprintf(f, "interface=%s\n", cfg->interface);
    fprintf(f, "\n[PORTS]\n");
    fprintf(f, "default_ports=");
    for (int i = 0; i < cfg->default_ports_count; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "%d", cfg->default_ports[i]);
    }
    fprintf(f, "\n");
    fprintf(f, "custom_ports=");
    for (int i = 0; i < cfg->custom_ports_count; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "%d", cfg->custom_ports[i]);
    }
    fprintf(f, "\n");
    
    fclose(f);
}

static void log_event(const char *event_type, int dest_port, int src_port, const char *protocol, const char *reason) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(f, "%s - %s: dest_port=%d, src_port=%d, protocol=%s, reason=%s\n",
            timestamp, event_type, dest_port, src_port, protocol, reason);
    fclose(f);
}

static void write_status(const char *status) {
    FILE *f = fopen(STATUS_FILE, "w");
    if (f) {
        fprintf(f, "%s", status);
        fclose(f);
    }
}

static char *read_status(void) {
    static char status[16] = "OFFLINE";
    FILE *f = fopen(STATUS_FILE, "r");
    if (f) {
        if (fgets(status, sizeof(status), f)) {
            status[strcspn(status, "\n\r")] = '\0';
        }
        fclose(f);
    }
    return status;
}

static void update_ports(const char *action, const char *ports_str) {
    struct config cfg;
    if (parse_config(&cfg) < 0) {
        fprintf(stderr, "Ошибка чтения конфигурации\n");
        return;
    }
    
    int ports[256];
    int count = 0;
    char *str = strdup(ports_str);
    char *token = strtok(str, ",");
    while (token && count < 256) {
        ports[count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    
    if (strcmp(action, "add") == 0) {
        for (int i = 0; i < count; i++) {
            int found = 0;
            for (int j = 0; j < cfg.custom_ports_count; j++) {
                if (cfg.custom_ports[j] == ports[i]) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                cfg.custom_ports[cfg.custom_ports_count++] = ports[i];
            }
        }
    } else if (strcmp(action, "del") == 0) {
        for (int i = 0; i < count; i++) {
            for (int j = 0; j < cfg.custom_ports_count; j++) {
                if (cfg.custom_ports[j] == ports[i]) {
                    for (int k = j; k < cfg.custom_ports_count - 1; k++) {
                        cfg.custom_ports[k] = cfg.custom_ports[k + 1];
                    }
                    cfg.custom_ports_count--;
                    break;
                }
            }
        }
    }
    
    write_config(&cfg);
    free(str);
}

static void show_settings(void) {
    struct config cfg;
    if (parse_config(&cfg) < 0) {
        fprintf(stderr, "Ошибка чтения конфигурации\n");
        return;
    }
    
    printf("\nТекущие настройки SyharikFW:\n");
    printf(" ┌──────────────────────────────────┐\n");
    printf("│ Всё кроме L7: %-18s\n", cfg.strict_mode ? "Включено" : "Отключено");
    printf("│ Разрешить DNS: %-24s\n", cfg.allow_dns ? "Да" : "Нет");
    printf("│ Разрешить ICMP: %-23s\n", cfg.allow_icmp ? "Да" : "Нет");
    printf("│ Интерфейс: %-27s\n", cfg.interface);
    printf("│ Стандартные порты: ");
    for (int i = 0; i < cfg.default_ports_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", cfg.default_ports[i]);
    }
    printf("\n");
    printf("│ Пользовательские порты: ");
    for (int i = 0; i < cfg.custom_ports_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", cfg.custom_ports[i]);
    }
    printf("\n");
    
    int all_ports[256];
    int all_count = 0;
    for (int i = 0; i < cfg.default_ports_count; i++) {
        all_ports[all_count++] = cfg.default_ports[i];
    }
    for (int i = 0; i < cfg.custom_ports_count; i++) {
        int found = 0;
        for (int j = 0; j < all_count; j++) {
            if (all_ports[j] == cfg.custom_ports[i]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            all_ports[all_count++] = cfg.custom_ports[i];
        }
    }
    printf("│ Разрешённые порты: ");
    for (int i = 0; i < all_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", all_ports[i]);
    }
    printf("\n");
    printf(" └──────────────────────────────────┘\n");
}

static void detach_xdp(const char *interface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off 2>/dev/null", interface);
    int ret = system(cmd);
    (void)ret;
    snprintf(cmd, sizeof(cmd), "bpftool net detach xdp dev %s 2>/dev/null", interface);
    ret = system(cmd);
    (void)ret;
}

static void cleanup(void) {
    if (ifindex >= 0 && skel) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    if (skel) {
        firewall_bpf__destroy(skel);
        skel = NULL;
    }
    write_status("OFFLINE");
}

static void signal_handler(int sig) {
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    const char *proto_str = "UNKNOWN";
    if (e->protocol == IPPROTO_TCP) proto_str = "TCP";
    else if (e->protocol == IPPROTO_UDP) proto_str = "UDP";
    else if (e->protocol == IPPROTO_ICMP) proto_str = "ICMP";
    
    log_event("BLOCKED", e->dest_port, e->src_port, proto_str, e->reason);
    printf("BLOCKED dest=%d src=%d proto=%s reason=%s\n",
           e->dest_port, e->src_port, proto_str, e->reason);
    return 0;
}

static int run_firewall(const char *interface_arg) {
    struct config cfg;
    if (parse_config(&cfg) < 0) {
        fprintf(stderr, "Ошибка чтения конфигурации\n");
        return 1;
    }
    
    const char *interface = interface_arg ? interface_arg : cfg.interface;
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Интерфейс %s не найден\n", interface);
        return 1;
    }
    
    skel = firewall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Ошибка загрузки BPF программы\n");
        return 1;
    }
    
    __u32 key;
    __u8 value;
    
    int settings_fd = bpf_map__fd(skel->maps.settings);
    key = 0; value = cfg.strict_mode ? 1 : 0;
    bpf_map_update_elem(settings_fd, &key, &value, BPF_ANY);
    
    key = 1; value = cfg.allow_dns ? 1 : 0;
    bpf_map_update_elem(settings_fd, &key, &value, BPF_ANY);
    
    key = 2; value = cfg.allow_icmp ? 1 : 0;
    bpf_map_update_elem(settings_fd, &key, &value, BPF_ANY);
    
    int ports_fd = bpf_map__fd(skel->maps.allowed_ports);
    
    __u16 port_key = 0;
    __u16 next_key = 0;
    while (bpf_map_get_next_key(ports_fd, &port_key, &next_key) == 0) {
        bpf_map_delete_elem(ports_fd, &port_key);
        port_key = next_key;
    }
    if (next_key != 0) {
        bpf_map_delete_elem(ports_fd, &next_key);
    }
    
    for (int i = 0; i < cfg.default_ports_count; i++) {
        __u16 port = cfg.default_ports[i];
        __u8 val = 1;
        bpf_map_update_elem(ports_fd, &port, &val, BPF_ANY);
    }
    for (int i = 0; i < cfg.custom_ports_count; i++) {
        __u16 port = cfg.custom_ports[i];
        __u8 val = 1;
        bpf_map_update_elem(ports_fd, &port, &val, BPF_ANY);
    }
    
    int prog_fd = bpf_program__fd(skel->progs.filter_traffic);
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "Ошибка прикрепления XDP: %s\n", strerror(-err));
        firewall_bpf__destroy(skel);
        skel = NULL;
        return 1;
    }
    
    write_status("ONLINE");
    
    printf("\nSyharikFW включен на интерфейсе %s\n", interface);
    printf("Разрешенные порты: ");
    for (int i = 0; i < cfg.default_ports_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", cfg.default_ports[i]);
    }
    for (int i = 0; i < cfg.custom_ports_count; i++) {
        printf(", %d", cfg.custom_ports[i]);
    }
    printf("\n");
    printf("Всё кроме L7: %s\n", cfg.strict_mode ? "Включено" : "Отключено");
    printf("DNS разрешен: %s\n", cfg.allow_dns ? "Да" : "Нет");
    printf("ICMP разрешен: %s\n", cfg.allow_icmp ? "Да" : "Нет");
    printf("\nНажмите Ctrl+C для остановки...\n");
    
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Ошибка создания ring buffer\n");
        cleanup();
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            break;
        }
    }
    
    ring_buffer__free(rb);
    cleanup();
    printf("\nSyharikFW остановлен\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (strcmp(argv[1], "--add") == 0) {
            if (argc < 3) {
                fprintf(stderr, "Error: Введите порты через запятую\n");
                return 1;
            }
            update_ports("add", argv[2]);
            printf("Добавлены порты: %s\n", argv[2]);
            show_settings();
        } else if (strcmp(argv[1], "--del") == 0) {
            if (argc < 3) {
                fprintf(stderr, "Error: Введите порты через запятую\n");
                return 1;
            }
            update_ports("del", argv[2]);
            printf("Удалены порты: %s\n", argv[2]);
            show_settings();
        } else if (strcmp(argv[1], "--list") == 0) {
            show_settings();
        } else if (strcmp(argv[1], "--run") == 0) {
            const char *iface = argc > 2 ? argv[2] : NULL;
            return run_firewall(iface);
        } else if (strcmp(argv[1], "--status") == 0) {
            printf("%s\n", read_status());
        } else if (strcmp(argv[1], "--detach") == 0) {
            if (argc < 3) {
                fprintf(stderr, "Укажите интерфейс: --detach <iface>\n");
                return 1;
            }
            detach_xdp(argv[2]);
            write_status("OFFLINE");
            printf("XDP снят с интерфейса %s\n", argv[2]);
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Использование:\n");
            printf("  Активация SyharikFW: sudo ./firewall [interface]\n");
            printf("  Добавление портов: sudo ./firewall --add port1,port2,...\n");
            printf("  Удаление портов: sudo ./firewall --del port1,port2,...\n");
            printf("  Показ настроек: sudo ./firewall --list\n");
            printf("  Запуск: sudo ./firewall --run [iface]\n");
            printf("  Статус: sudo ./firewall --status\n");
            printf("  Снять XDP: sudo ./firewall --detach <iface>\n");
            printf("  Помощь: sudo ./firewall --help\n");
        } else {
            fprintf(stderr, "Неизвестная команда: %s\n", argv[1]);
            return 1;
        }
    } else {
        printf("╔══════════════════════════════════╗\n");
        printf("║     SyharikFW by syharik3316     ║\n");
        printf("║               V2.0               ║\n");
        printf("╠══════════════════════════════════╣\n");
        printf("║ Используйте --help для справки  ║\n");
        printf("║ или --run для запуска firewall  ║\n");
        printf("╚══════════════════════════════════╝\n");
        show_settings();
    }
    
    return 0;
}

