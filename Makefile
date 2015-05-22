main: all

all: myresolver

myresolver:
	gcc -w -std=c99 -oterm myresolver.c -o myresolver
clean: 
	rm myresolver
	
