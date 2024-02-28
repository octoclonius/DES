CC := g++
CFLAGS := -std=c++20 -Wall

TARGET := DES

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
