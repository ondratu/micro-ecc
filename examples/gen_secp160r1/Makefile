CFLAGS=-I../../

all: gen_secp160r1 secp160r1_sig

uECC.o: ../../uECC.c
	$(CC) $(CFLAGS) -c -o $@ $<

gen_secp160r1: gen_secp160r1.o uECC.o
	$(CC) gen_secp160r1.o uECC.o -o gen_secp160r1

secp160r1_sig: secp160r1_sig.o uECC.o
	$(CC) secp160r1_sig.o uECC.o -o secp160r1_sig

