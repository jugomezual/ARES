#include "network_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_BUF   1024
#define MAX_HOSTS  256
#define MAX_PORTS  100
#define MAX_IP_LEN 64   /* enough for IPv4, IPv6 or a short hostname */

typedef struct {
    char ip[MAX_IP_LEN];
    int  ports[MAX_PORTS];
    int  port_count;
} Host;

/*
 * Extract the IP / hostname from a "Nmap scan report for …" line.
 * Handles two forms nmap uses:
 *   "Nmap scan report for 10.0.0.1"
 *   "Nmap scan report for hostname (10.0.0.1)"
 * In the second form the raw IP inside the parentheses is preferred.
 */
static void extract_ip(const char *line, char *dst, size_t dst_len)
{
    const char *p = line + strlen("Nmap scan report for ");

    /* If a parenthesised IP exists, use it */
    const char *paren = strrchr(p, '(');
    if (paren) {
        paren++;
        const char *end = strchr(paren, ')');
        if (end) {
            size_t len = (size_t)(end - paren);
            if (len >= dst_len) len = dst_len - 1;
            memcpy(dst, paren, len);
            dst[len] = '\0';
            return;
        }
    }

    /* Plain IP / hostname — copy and strip trailing whitespace */
    strncpy(dst, p, dst_len - 1);
    dst[dst_len - 1] = '\0';
    size_t len = strlen(dst);
    while (len > 0 &&
           (dst[len - 1] == '\n' || dst[len - 1] == '\r' || dst[len - 1] == ' '))
        dst[--len] = '\0';
}

/*
 * Try to parse a port line such as "22/tcp   open  ssh".
 * Returns the port number on success, -1 if the line doesn't match.
 */
static int parse_port_line(const char *line)
{
    int  port;
    char proto[16];
    char state[16];

    /* sscanf: PORT/PROTO   STATE   SERVICE */
    if (sscanf(line, "%d/%15s %15s", &port, proto, state) == 3 &&
        strcmp(state, "open") == 0 &&
        port > 0 && port <= 65535)
    {
        return port;
    }
    return -1;
}

int run_network_scan(const char *network)
{
    if (!network) {
        fprintf(stderr, "No network provided\n");
        return 1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nmap -T4 -F --open %s 2>/dev/null", network);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("Failed to run nmap");
        return 1;
    }

    Host hosts[MAX_HOSTS];
    int  host_count = 0;
    int  cur        = -1;   /* index of the host currently being parsed */
    char line[LINE_BUF];

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Nmap scan report for ", 21) == 0) {
            if (host_count < MAX_HOSTS) {
                cur = host_count++;
                hosts[cur].port_count = 0;
                extract_ip(line, hosts[cur].ip, MAX_IP_LEN);
            }
        } else if (cur >= 0) {
            int port = parse_port_line(line);
            if (port != -1 && hosts[cur].port_count < MAX_PORTS)
                hosts[cur].ports[hosts[cur].port_count++] = port;
        }
    }

    pclose(fp);

    /* ── Emit compact JSON ── */
    printf("{\"hosts\":[");
    for (int i = 0; i < host_count; i++) {
        if (i > 0) printf(",");
        printf("{\"ip\":\"%s\",\"ports\":[", hosts[i].ip);
        for (int j = 0; j < hosts[i].port_count; j++) {
            if (j > 0) printf(",");
            printf("%d", hosts[i].ports[j]);
        }
        printf("]}");
    }
    printf("]}\n");

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network>\n", argv[0]);
        return 1;
    }
    return run_network_scan(argv[1]);
}
