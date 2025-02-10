CC = gcc
CFLAGS = -ggdb -Wall

.PHONY: all
all: spoofd_ssh

spoofd_ssh: spoofd_ssh.c
	$(CC) -o spoofd_ssh spoofd_ssh.c

.PHONY: clean
clean:
	rm -f *.o spoofd_ssh
