CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -D_GNU_SOURCE
TARGET = pacfetch
INSTALL_DIR = /usr/local/bin

all: $(TARGET)

$(TARGET): pacfetch.c
	$(CC) $(CFLAGS) -o $(TARGET) pacfetch.c

install: $(TARGET)
	cp $(TARGET) $(INSTALL_DIR)/
	chmod 755 $(INSTALL_DIR)/$(TARGET)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)