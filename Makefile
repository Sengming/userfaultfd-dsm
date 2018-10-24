CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

CC = gcc
CFLAGS += -g -O2 -Wall -pthread
LDFLAGS +=

DEPS_DIR  := $(CUR_DIR)/.deps$(LIB_SUFFIX)
DEPCFLAGS = -MD -MF $(DEPS_DIR)/$*.d -MP

SRC_FILES = $(wildcard *.c)
OBJ_FILES := bus_functions.o userfault_handler.o dsm_userspace.o msi_statemachine.o

EXE_FILES = $(SRC_FILES:.c=)

%.o:%.c $(DEPS_DIR)
	$(CC) $(CFLAGS) $(DEPCFLAGS) -c $(input) -o $(output)

dsm_userspace: $(OBJ_FILES)
	$(CC) -o $@ $(CFLAGS) $(OBJ_FILES) $(LDFLAGS)

all: $(EXE_FILES)
	echo $(EXE_FILES)

clean:
	rm -f dsm_userspace $(OBJ_FILES)

.PHONY: all clean
