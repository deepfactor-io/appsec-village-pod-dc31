CFLAGS= -fPIC -Wall -Werror

SO_OBJS= libexercise2.o

all : libexercise2.so exercise2a exercise2b

libexercise2.so : libexercise2.c $(SO_OBJS)
	$(CC) -shared -o libexercise2.so $(SO_OBJS)

exercise2a : exercise2a.c
	$(CC) -o exercise2a exercise2a.c

exercise2b : exercise2b.c
	$(CC) -o exercise2b exercise2b.c

clean :
	$(RM) $(SO_OBJS) libexercise2.so exercise2a exercise2b
