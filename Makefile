CC = gcc
CFLAGS = -g -Wno-incompatible-pointer-types -Wno-implicit-function-declaration
TARGET = packet-replay
OBJECTS = main.o options.o logger.o pcap.o send.o crc32.o

all : $(TARGET)
$(TARGET) : $(OBJECTS)
		$(CC) $(CFLAGS) -o $@ $^

clean : 
	rm *.o packet-replay

