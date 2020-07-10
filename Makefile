CC=gcc
CFLAGS=-I. -lstdc++
DEPS = uvmac.h
OBJ = authenticate.cc uvmac.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

authenticate: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
