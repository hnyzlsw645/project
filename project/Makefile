CC	=	gcc
CFLAGS= -O2
#LDFLAGS	=	-lpthread
LDFLAGS	=
PROGRAM	=	libTassApi_LINUX_32
INCLUDE_PATH =  -I./inc/
SRCDIRS = ./src/
LIBPATH = ./dist/linux_x64/

ifeq ($(shell getconf LONG_BIT), 32)
    LIBPATH = ./dist/linux_x86/
	CFLAGS	= -O2 -m32 
	PROGRAM = libTassApi_LINUX_32.so
else
    LIBPATH = ./dist/linux_x64/
	CFLAGS	= -O2 -fPIC -DUSE_MMAP -m64 
	PROGRAM = libTassApi_LINUX_64.so
endif

OBJS	=	hsmapi_log.o\
		hsmapi_tools.o\
		hsmsocket.o \
		hsmapi_init.o\
		hsmapi_ic.o\
		hsmapi_racal.o\
		hsmapi_asym.o\
		hsmapi_der.o\
		hsmapi.o

$(PROGRAM):$(OBJS)
	rm -f $(PROGRAM)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@
	cp -f $(PROGRAM) $(LIBPATH)
	rm -f *.o
	@echo "Successful compilation"

test:
	gcc -o ./bin/test $(SRCDIRS)test.c -g $(INCLUDE_PATH) -L./ $(PROGRAM) -ldl -DUNIX

hsmapi_log.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_log.c $(INCLUDE_PATH)

hsmapi_tools.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_tools.c $(INCLUDE_PATH)

hsmsocket.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmsocket.c $(INCLUDE_PATH)

hsmapi_init.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_init.c $(INCLUDE_PATH)

hsmapi_ic.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_ic.c $(INCLUDE_PATH)

hsmapi_racal.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_racal.c $(INCLUDE_PATH)

hsmapi_asym.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_asym.c $(INCLUDE_PATH)
	
hsmapi_der.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi_der.c $(INCLUDE_PATH)

hsmapi.o:
	$(CC) $(CFLAGS) -c $(SRCDIRS)hsmapi.c $(INCLUDE_PATH)

.PHONY: clean  distclean test
clean:
	rm $(OBJS) $(PROGRAM) 

distclean: clean
	rm $(DEPS) TAGS
	
test:

