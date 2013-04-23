SRCS=src/main.c src/wrath-args.c src/wrath-reactor.c src/wrath-injector.c src/wrath-builders.c
OBJS=main.o wrath-args.o wrath-injector.o wrath-reactor.o wrath-builders.o

cleandir: wrath
	  mv $(OBJS) objs	 

wrath: 	objects	
	$(CC) -o wrath $(OBJS) -lpcap -lnet

objects: $(SRCS)
	 $(CC) -c $(SRCS)
