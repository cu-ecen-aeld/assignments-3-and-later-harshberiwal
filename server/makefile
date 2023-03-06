CC= $(CROSS_COMPILE)gcc
.PHONY : all

all:aesdsocket.c
	$(CC) aesdsocket.c -Wall -Werror -o aesdsocket -lpthread -lrt
	 
.PHONY:clean
clean:
	rm -f *.o aesdsocket



