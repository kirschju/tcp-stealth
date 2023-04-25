CC=gcc
CFLAGS=
SERVER_OBJS = server.c
CLIENT_OBJS = client.c
ALL_OBJS = authserver authserver6 authclient authclient6 intserver intserver6 intclient intclient6

all: $(ALL_OBJS)

authserver: $(SERVER_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV4_EXAMPLE
authserver6: $(SERVER_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV6_EXAMPLE
authclient: $(CLIENT_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV4_EXAMPLE
authclient6: $(CLIENT_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV6_EXAMPLE
intserver: $(SERVER_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV4_EXAMPLE -DDO_INTEGRITY
intserver6: $(SERVER_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV6_EXAMPLE -DDO_INTEGRITY
intclient: $(CLIENT_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV4_EXAMPLE -DDO_INTEGRITY
intclient6: $(CLIENT_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -DIPV6_EXAMPLE -DDO_INTEGRITY

.PHONY: clean
clean:
	rm -rf $(ALL_OBJS)
