

main:main.o pcap.o analyse.o
	gcc -g -Wall main.c pcap.o analyse.o -o main

pcap.o:pcap.c pcap.h
	gcc -g -Wall -c pcap.c 

analyse.o:analyse.c analyse.h
	gcc -g -Wall -c analyse.c

clean:
	rm -f *.o main
