CC = gcc
CFLAGS = -std=c99
gSendDIR =./sender
gRecDIR =./receiver
fileServer =./
fileClient =./



all: gsend grec file_server file_client
.PHONY: clean

gsend:
	$(CC) $(CFLAGS) $(gSendDIR)/gsend.c -o gsend -lcrypto

file_server:
	$(CC) $(CFLAGS) $(fileServer)/file_server.c -o file_server

file_client:
	$(CC) $(CFLAGS) $(fileClient)/file_client.c -o file_client

grec: 
	$(CC) $(CFLAGS) $(gRecDIR)/grec.c -o grec -lcrypto
clean:
	rm gsend
	rm file_server
	rm file_client
	rm grec
