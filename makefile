PRJ_ROOT        = .
BINARY          = sha3_test
OBJS            = sha3.o hmac_sha3.o tests.o
CC              = gcc
CFLAGS          = -Wall
SRC_DIR         = $(PRJ_ROOT)/src
TESTS_DIR       = $(PRJ_ROOT)/tests
INCLUDES        = -I$(PRJ_ROOT)/inc

SRC             = $(SRC_DIR)/sha3.c \
		  $(SRC_DIR)/hmac_sha3.c \
		  $(TESTS_DIR)/tests.c

$(BINARY):
	@mkdir -p "bin"
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) -o bin/$(BINARY)


clean:
	rm -rf  bin
