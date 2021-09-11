all: 
	gcc -o yaclient yaclient.c -lssl -lcrypto -lpthread -w
	gcc -o yaserver yaserver.c -lssl -lcrypto -lpthread -lcrypt -w

clean: 
	rm yaclient yaserver

