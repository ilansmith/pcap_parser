CC=gcc
CFLAGS=-Wall -Werror -O0 -g
APP=test
OBJS=pcap.o test.o

CONFIG_DEBUG=y

ifeq ($(CONFIG_DEBUG),y)
	CFLAGS+=-DCONFIG_DEBUG
endif

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanall

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	@echo "removing executables"
	@rm -f $(APP)
	@echo "removing object files"
	@rm -f *.o *.a

cleanall: clean
	@echo "removing pre compilation files"
	@rm -f *_pre.c
	@echo "removing tag file"
	@rm -f tags

