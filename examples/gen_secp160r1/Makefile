CFLAGS=-I../../

all: gen_secp160r1

uECC.o: ../../uECC.c
	$(CC) $(CFLAGS) -c -o $@ $<

gen_secp160r1: gen_secp160r1.o uECC.o
	$(CC) gen_secp160r1.o uECC.o -o gen_secp160r1
