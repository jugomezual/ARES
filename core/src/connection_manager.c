#include "connection_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Variable estática para guardar la conexión única
static Connection connection;
static int connection_initialized = 0;

int add_connection(ConnectionType type, const char *ip, int port,
                   const char *user, const char *password)
{
    if (connection_initialized)
    {
        printf("Ya existe una conexión activa.\n");
        return -1;  // Error: conexión ya existe
    }

    connection.id = 1;  // Solo una conexión, id fijo
    connection.type = type;
    connection.status = CONN_STATUS_CONNECTING;
    strncpy(connection.ip, ip, sizeof(connection.ip) - 1);
    connection.ip[sizeof(connection.ip) - 1] = '\0';
    connection.port = port;
    strncpy(connection.user, user, sizeof(connection.user) - 1);
    connection.user[sizeof(connection.user) - 1] = '\0';
    strncpy(connection.password, password, sizeof(connection.password) - 1);
    connection.password[sizeof(connection.password) - 1] = '\0';
    strcpy(connection.details, "Conectando...");

    printf("Intentando conectar a %s:%d como %s\n", connection.ip,
           connection.port, connection.user);

    // Ejecución según tipo
    if (type == CONN_TYPE_VPN)
    {
        // Aquí en el futuro: comando real PPTP
        // Ejemplo con pptpsetup (comentar para ahora)
        /*
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "sudo pptpsetup --create vpnconn --server %s --username %s "
                 "--password %s --encrypt --start",
                 connection.ip, connection.user, connection.password);

        int ret = system(cmd);
        if (ret != 0)
        {
            connection.status = CONN_STATUS_FAILED;
            strcpy(connection.details, "Error en conexión PPTP.");
            return 1;
        }
        */
        connection.status = CONN_STATUS_CONNECTED;
        strcpy(connection.details, "Conexión VPN establecida (simulada).");
    }
    else if (type == CONN_TYPE_NCAT)
    {
        // Base lista para Netcat
        connection.status = CONN_STATUS_CONNECTED;
        strcpy(connection.details, "Conexión Ncat establecida (simulada).");
    }
    else
    {
        connection.status = CONN_STATUS_FAILED;
        strcpy(connection.details, "Tipo de conexión no soportado.");
        return 1;
    }

    connection_initialized = 1;
    printf("Conexión establecida.\n");
    return 0;  // Éxito
}

ConnectionStatus get_connection_status()
{
    if (!connection_initialized)
        return CONN_STATUS_DISCONNECTED;
    return connection.status;
}

void disconnect_connection()
{
    if (!connection_initialized)
    {
        printf("No hay conexión activa para desconectar.\n");
        return;
    }
    connection.status = CONN_STATUS_DISCONNECTED;
    strcpy(connection.details, "Conexión desconectada.");
    connection_initialized = 0;

    printf("Conexión desconectada.\n");
}

void print_connection()
{
    if (!connection_initialized)
    {
        printf("No hay conexión activa.\n");
        return;
    }
    printf("Conexión ID: %d\n", connection.id);
    printf("Tipo: %d\n", connection.type);
    printf("Estado: %d\n", connection.status);
    printf("IP: %s\n", connection.ip);
    printf("Puerto: %d\n", connection.port);
    printf("Usuario: %s\n", connection.user);
    // No mostramos password por seguridad
    printf("Detalles: %s\n", connection.details);
}
