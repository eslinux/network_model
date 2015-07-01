all: hmac

hmac: test-hmac.o hmac.o sha2.o
	$(CC) test-hmac.o sha2.o hmac.o -o hmac
	
test-hmac.o:test-hmac.c
	$(CC) -Wall -c test-hmac.c -o test-hmac.o
	
hmac.o: hmac_sha2.c hmac_sha2.h
	$(CC) -Wall -c hmac_sha2.c -o hmac.o

sha2.o: sha2.c sha2.h
	$(CC) -Wall -c sha2.c -o sha2.o

clean:
	- rm -rf *.o hmac
