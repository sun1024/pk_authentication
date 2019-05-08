CC=clang
CFLAGS=-std=c11 -O0 -g -ggdb -Wall -pedantic
LDFLAGS=-O0 -lcrypto -g -ggdb -Wall -pedantic

all: client

client: main.o
        $(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
        $(CC) -c -o $@ $(CFLAGS) $<

        openssl genrsa -out app.key 4096 && openssl rsa -in app.key -pubout -out pubapp.key
