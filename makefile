SRCS=src/main.c src/wrath-args.c

wrath: 	objs
	$(CC) -o wrath objs/*.o

movement: 	objects	
		mv src/*.o objs	

objects: $(SRCS)
	 $(CC) -c $(SRCS)
