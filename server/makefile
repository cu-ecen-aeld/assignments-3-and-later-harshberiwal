all: aesdsocket

CROSS_COMPILE = 
CC ?= $(CROSS_COMPILE)gcc

LDFLAGS?= -lpthread -lrt

aesdsocket: aesdsocket.c
	$(CC) aesdsocket.c $(LDFLAGS) -Wall -Werror -g -o aesdsocket

clean:
	rm -rf *.o aesdsocket 
