CC?=gcc
CFLAGS?=-g -I/usr/local/libev-4.22/include
LDFLAGS?=-L/usr/local/libev-4.22/lib
LIBS?=-lev

all:test
.PHONY:all

target = test
objects = main.o server.o


$(target):$(objects)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(objects):%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY:clean
	
clean:
	rm -rf *.o $(target) $(target)
