TARGETS = thttp-example1

all: $(TARGETS)


thttp-example1: thttp.c thttp.h \
		trest.c trest.h \
		thttp-example1.c \
		tinyhttp/chunk.c tinyhttp/chunk.h \
		tinyhttp/header.c tinyhttp/header.h \
		tinyhttp/http.c tinyhttp/http.h \
		jsmn/jsmn.c jsmn/jsmn.h
	$(CC) $(CFLAGS) -o $@ \
		$(filter %.c, $^)

clean:
	rm $(TARGETS)

install:
	install -d $(PREFIX)/bin/ 
	install -D $(TARGET) $(PREFIX)/bin/

