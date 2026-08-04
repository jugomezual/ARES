#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

typedef enum
{
    CONN_TYPE_VPN,
    CONN_TYPE_NCAT,
    CONN_TYPE_SSH,
    CONN_TYPE_METASPLOIT
} ConnectionType;

typedef enum
{
    CONN_STATUS_DISCONNECTED,
    CONN_STATUS_CONNECTING,
    CONN_STATUS_CONNECTED,
    CONN_STATUS_FAILED
} ConnectionStatus;

typedef struct
{
    int id;
    ConnectionType type;
    ConnectionStatus status;
    char ip[16];
    int port;
    char user[64];
    char password[64];  // Nuevo campo
    char details[256];
} Connection;

int add_connection(ConnectionType type, const char *ip, int port,
                   const char *user, const char *password);

ConnectionStatus get_connection_status();

void disconnect_connection();

void print_connection();

#endif
