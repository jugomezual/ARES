CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

# Archivos fuente para cada ejecutable
VPN_SRC = src/connection_manager.c src/vpn_connect.c
VPN_OBJ = $(VPN_SRC:.c=.o)
VPN_TARGET = vpn_connect

SCAN_SRC = src/connection_manager.c src/network_scan.c
SCAN_OBJ = $(SCAN_SRC:.c=.o)
SCAN_TARGET = network_scan

# Por defecto compila ambos
all: $(VPN_TARGET) $(SCAN_TARGET)

# vpn_connect
$(VPN_TARGET): $(VPN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# network_scan
$(SCAN_TARGET): $(SCAN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Reglas para .o (se reutilizan para ambos)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o $(VPN_TARGET) $(SCAN_TARGET)

run: $(VPN_TARGET)
	./$(VPN_TARGET)
