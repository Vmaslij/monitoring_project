CC=g++
CFLAGS=-c -fPIC
DIR_OUT=bin

all: main

main: main.o lib_analizator.a
	$(CC) $(DIR_OUT)/main.o -L$(DIR_OUT) -l_analizator -o $(DIR_OUT)/main

main.o: makedir main.cpp
	$(CC) $(CFLAGS) main.cpp -o $(DIR_OUT)/main.o

lib_analizator.a: makedir getifconf.cpp
	$(CC) $(CFLAGS) getifconf.cpp -o $(DIR_OUT)/getifconf.o
	ar rcs $(DIR_OUT)/lib_analizator.a $(DIR_OUT)/getifconf.o

makedir:
	mkdir -p $(DIR_OUT)

clean:
	rm -rf $(DIR_OUT)/*
