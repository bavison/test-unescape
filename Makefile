#CFLAGS=-g -fprofile-arcs -ftest-coverage
CFLAGS=-O2

test-unescape: main.o unescape.o
	gcc ${CFLAGS} -o $@ $^

main.o: main.c
	gcc -c ${CFLAGS} -Wall -Wextra -o $@ $^

unescape.o: unescape.S
	gcc -I../ffmpeg -I../ffmpeg-aarch32 -c -o $@ $^

clean:
	rm -f *.o test-unescape
