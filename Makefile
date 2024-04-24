CC = gcc
CFLAGS = -g -pthread -Wno-incompatible-pointer-types -Wno-implicit-function-declaration -Wno-int-conversion
TARGET = packet-replay
OBJECTS = main.o options.o logger.o pcap.o send.o crc32.o server.o

all : $(TARGET)
$(TARGET) : $(OBJECTS)
		$(CC) $(CFLAGS) -o $@ $^

clean : 
	rm *.o packet-replay

