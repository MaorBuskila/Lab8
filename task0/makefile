all: myELF

myELF: myELF.o
	gcc -g -Wall -o myELF myELF.o

myELF.o: myELF.c
	gcc -g -Wall -c -o myELF.o myELF.c

.PHONY: clean

clean:
	rm -f *.o myELF