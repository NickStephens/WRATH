# Source files
SRCS=src/main.c src/wrath-args.c src/wrath-reactor.c src/wrath-injector.c src/wrath-builders.c src/wrath-http.c src/wrath-generic-app.c

# Resultant object code
OBJS=main.o wrath-args.o wrath-injector.o wrath-reactor.o wrath-builders.o wrath-http.o wrath-generic-app.o

# Manpage installation directory
MANDIR=/usr/share/man/man8

# Binary installation directory
INSTALLDIR=/usr/sbin

all: compile
	 $(CC) $(CFLAGS) -o wrath $(OBJS) -lpcap -lnet
	
compile: $(SRCS)
	 $(CC) $(CFLAGS) -c $(SRCS)

clean: 
	rm -f *.o wrath

install: 
	cp wrath $(INSTALLDIR)
	cp man/wrath.8 $(MANDIR)
