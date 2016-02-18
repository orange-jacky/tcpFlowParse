 CC =	gcc
 CFLAGS = -g -O0 -W -Wall -Wpointer-arith -Wno-unused-parameter -Wunused-function -Wunused-variable -Wunused-value
 CPP =	gcc -E
 LINK =	$(CC)
 RM = rm -rf

#output obj,bin directory
curdir = $(shell pwd)
objsdir = $(curdir)/obj
bindir = $(curdir)/bin
srcdir = $(curdir)/src
incdir = $(curdir)/inc
logdir = $(curdir)/var

ALL_INCS = -I inc  -I /usr/include/libxml2

ALL_DEPS = $(incdir/tcpFlowParse.h \
	$(incdir)/cups.h

$(bindir)/tcpFlowParse: $(objsdir)/tcpFlowParse.o \
	$(objsdir)/log.o \
	$(objsdir)/util.o \
	$(objsdir)/xmlXpath.o \
	$(objsdir)/datalink.o \
	$(objsdir)/tcpip.o \
	$(objsdir)/cups.o \
	$(objsdir)/list.o 

	$(LINK) -o $(bindir)/tcpFlowParse \
	$(objsdir)/tcpFlowParse.o \
	$(objsdir)/log.o \
	$(objsdir)/util.o \
	$(objsdir)/xmlXpath.o \
	$(objsdir)/tcpip.o \
	$(objsdir)/datalink.o \
	$(objsdir)/cups.o \
	$(objsdir)/list.o \
	-lxml2 -lpcap

$(objsdir)/tcpFlowParse.o:	$(ALL_DEPS)\
	$(srcdir)/tcpFlowParse.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/tcpFlowParse.o \
		$(srcdir)/tcpFlowParse.c


$(objsdir)/xmlXpath.o:	$(ALL_DEPS)\
	$(srcdir)/xmlXpath.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/xmlXpath.o \
		$(srcdir)/xmlXpath.c


$(objsdir)/log.o:	$(ALL_DEPS)\
	$(srcdir)/log.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/log.o \
		$(srcdir)/log.c

$(objsdir)/util.o:	$(ALL_DEPS)\
	$(srcdir)/util.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/util.o \
		$(srcdir)/util.c

$(objsdir)/datalink.o:	$(ALL_DEPS)\
	$(srcdir)/datalink.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/datalink.o \
		$(srcdir)/datalink.c

$(objsdir)/tcpip.o:	$(ALL_DEPS)\
	$(srcdir)/tcpip.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/tcpip.o \
		$(srcdir)/tcpip.c

$(objsdir)/cups.o:	$(ALL_DEPS)\
	$(srcdir)/cups.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/cups.o \
		$(srcdir)/cups.c		

$(objsdir)/list.o:	$(ALL_DEPS)\
	$(srcdir)/list.c
	$(CC) -c $(CFLAGS) $(ALL_INCS) \
		-o $(objsdir)/list.o \
		$(srcdir)/list.c

#test -d '$(objsdir)'  ||  mkdir -p $(objsdir)
#test -d '$(bindir)'   ||  mkdir -p $(bindir) 

clean:
	-$(RM) $(objsdir)/*
	-$(RM) $(bindir)/*
	-$(RM) $(logdir)/*

