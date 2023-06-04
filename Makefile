# HPKE Examples Makefile
CC       = gcc
LIB_PATH = /home/iwai/wolf/wolfssl
CFLAGS   = -Wall -I$(LIB_PATH)/include -include $(LIB_PATH)/wolfssl/options.h
LIBS     = -L$(LIB_PATH)/src/.libs

# option variables
DYN_LIB         = -lwolfssl
STATIC_LIB      = $(LIB_PATH)/src/.libs/libwolfssl.a
DEBUG_FLAGS     = -g -DDEBUG
DEBUG_INC_PATHS = -MD
OPTIMIZE        = -Os

# Options
LIBS+=$(DYN_LIB)

# build targets
SRC=$(wildcard *.c)
TARGETS=$(patsubst %.c, %, $(SRC))

all: $(TARGETS)
	rm -rf tmp
	mkdir tmp
	touch tmp/toSender
	touch tmp/toReceiver

# build template
%: %.c
	$(CC) -o $@ $< $(CFLAGS) $(STATIC_LIB) -g -lm

clean:
	rm -f $(TARGETS)
	rm -f *.pub
	rm -f *.enc
	rm -rf tmp
