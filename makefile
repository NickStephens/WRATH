# Source files
SRCS=src/main.c src/wrath-args.c src/wrath-reactor.c src/wrath-injector.c src/wrath-builders.c src/wrath-http.c src/wrath-generic-app.c

# Resultant object code
OBJS=main.o wrath-args.o wrath-injector.o wrath-reactor.o wrath-builders.o wrath-http.o wrath-generic-app.o

# Manpage installation directory
MANDIR=/usr/share/man/man8

# Binary installation directory
INSTALLDIR=/usr/sbin

install: clean
	cp wrath $(INSTALLDIR)
	cp man/wrath.8 $(MANDIR)
	
clean: wrath
	  mv $(OBJS) objs	 

wrath: 	objects	
	$(CC) -o wrath $(OBJS) -lpcap -lnet

objects: $(SRCS)
	 $(CC) -c $(SRCS)
