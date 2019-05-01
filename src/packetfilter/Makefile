CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lpcap

OBJS=vtap_pf.o

all: $(OBJS)
	$(CC) $(CFLAGS) -o vtap-pf $(OBJS) $(LDFLAGS)

.PHONY: clean

clean:
	/bin/rm -rf vtap-pf vtap_pf.o

