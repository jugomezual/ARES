// src/vpn_connect.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connection_manager.h"

// Declaramos la función que ya tienes
int add_connection(ConnectionType type, const char *ip, int port,
                   const char *user, const char *password);

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        printf("Uso: %s <tipo_conexion> <ip> <puerto> <usuario> <password>\n",
               argv[0]);
        printf("tipo_conexion: vpn\n");
        return 1;
    }

    const char *type_str = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);
    const char *user = argv[4];
    const char *password = argv[5];

    ConnectionType type;

    if (strcmp(type_str, "vpn") == 0)
    {
        type = CONN_TYPE_VPN;
    }
    else
    {
        printf("Tipo de conexion no soportado: %s\n", type_str);
        return 1;
    }

    // Llamamos a nuestra función de gestión de conexiones
    int result = add_connection(type, ip, port, user, password);
    if (result == 0)
    {
        printf("Conexión VPN establecida correctamente.\n");
    }
    else
    {
        printf("Error al establecer conexión VPN.\n");
    }
    return result;
}
