SRCS=src/main.c src/wrath-args.c
OBJS=main.o wrath-args.o

cleandir: wrath
	  mv $(OBJS) objs	 

wrath: 	objects	
	$(CC) -o wrath $(OBJS)

objects: $(SRCS)
	 $(CC) -c $(SRCS)
