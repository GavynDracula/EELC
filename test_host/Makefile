
all: main.c replay.c receive.c
	gcc -g -Wall -o eelc main.c replay.c receive.c -lpcap -lpthread

clean:
	rm -rf *.o eelc
