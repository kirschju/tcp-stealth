CC      = gcc
CFLAGS  = -shared -fPIC -rdynamic
LDFLAGS = -shared -ldl -e print_info
DEPS    = startup.h hooks.h startup.h knock.h list.h
OBJ     = startup.o hooks.o logsys.o knock.o list.o
OUT_OBJ = libknockify.so

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT_OBJ): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *.o $(OUT_OBJ)
