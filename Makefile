CC = gcc
CFLAGS = -O2 -Wall

all: monitor

monitor: monitor.c
	$(CC) $(CFLAGS) -o monitor monitor.c

clean:
	rm -f monitor
