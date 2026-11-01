CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wshadow -D_GNU_SOURCE
LDLIBS   = -lcrypto
B        = build

all: $(B)/device $(B)/mitm $(B)/sendfile $(B)/recvfile

$(B)/device: src/device.c src/dh.c src/pkt.c src/dh.h src/pkt.h | $(B)
	$(CC) $(CFLAGS) -o $@ src/device.c src/dh.c src/pkt.c $(LDLIBS)
$(B)/mitm: src/mitm.c src/pkt.c src/pkt.h | $(B)
	$(CC) $(CFLAGS) -o $@ src/mitm.c src/pkt.c
$(B)/sendfile: src/sendfile.c | $(B)
	$(CC) $(CFLAGS) -o $@ $<
$(B)/recvfile: src/recvfile.c | $(B)
	$(CC) $(CFLAGS) -o $@ $<
$(B):
	mkdir -p $(B)
clean:
	rm -rf $(B)
.PHONY: all clean
