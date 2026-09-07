CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE

SRCS = src/utils.c src/payload.c src/ethernet.c src/ipv4.c src/arp.c src/strm.c src/pcapng.c src/transmitter.c src/cli.c
OBJS = $(SRCS:.c=.o)

MAIN_SRC = src/main.c
MAIN_OBJ = src/main.o

TEST_SRC = tests/test_pktx.c
TEST_OBJ = tests/test_pktx.o

TARGET = pktx
TEST_TARGET = pktx_test

.PHONY: all clean test

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_TARGET): $(OBJS) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f src/*.o tests/*.o $(TARGET) $(TEST_TARGET) test_out.strm sample.strm converted_pcap.strm l2_stream.strm l3_stream.strm
