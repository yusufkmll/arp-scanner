# build an executable named myprog from myprog.c
all: atomictest.c 
	gcc -o att atomictest.c -lm -pthread
# -g -Wall
clean: 
	$(RM) atomictest
	