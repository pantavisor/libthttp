TARGET = login-client

all:
	$(CC) $(CFLAGS) -o $(TARGET) thttp.c main.c tinyhttp/chunk.c tinyhttp/header.c tinyhttp/http.c

clean:
	rm $(TARGET)

install:
	install -d $(PREFIX)/bin/ 
	install -D $(TARGET) $(PREFIX)/bin/
