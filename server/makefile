all: aesdsocket
<<<<<<< HEAD

CROSS_COMPILE = 
CC ?= $(CROSS_COMPILE)gcc
=======

CROSS_COMPILE = 
CC ?= $(CROSS_COMPILE)gcc

LDFLAGS?= -lpthread -lrt

aesdsocket: aesdsocket.c
	$(CC) aesdsocket.c $(LDFLAGS) -Wall -Werror -g -o aesdsocket

clean:
	rm -rf *.o aesdsocket 
>>>>>>> 425a65645fa668c3ea2fceb42569c1d1799ef33b

LDFLAGS?= -lpthread -lrt

aesdsocket: aesdsocket.c
	$(CC) aesdsocket.c $(LDFLAGS) -Wall -Werror -g -o aesdsocket

clean:
	rm -rf *.o aesdsocket 
