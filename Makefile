CC=clang
CFLAGS=-std=c11 -O0 -g -ggdb -Wall -pedantic
LDFLAGS=-O0 -lcrypto -g -ggdb -Wall -pedantic

all: star

star: main.o
		$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
		$(CC) -c -o $@ $(CFLAGS) $<
