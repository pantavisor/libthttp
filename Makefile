TARGETS = thttp-example1 trest-example1

CFLAGS := -g 

trest-example1_DEFINES := -DJSMN_PARENT_LINKS=1

all: $(TARGETS)

LIBTHTTP_PREREQ := \
	thttp.c thttp.h \
	tinyhttp/chunk.c tinyhttp/chunk.h \
	tinyhttp/header.c tinyhttp/header.h \
	tinyhttp/http.c tinyhttp/http.h \
	jsmn/jsmn.c jsmn/jsmn.h

LIBTREST_PREREQ := \
	$(LIBTHTTP_PREREQ) \
	trest.c trest.h \

thttp-example1: $(LIBTHTTP_PREREQ) thttp-example1.c
	$(CC) $(CFLAGS) -o $@ \
		$(filter %.c, $^)

trest-example1: $(LIBTREST_PREREQ) trest-example1.c
	$(CC) $(CFLAGS) $($@_DEFINES) -o $@ \
		$(filter %.c, $^)

clean:
	rm $(TARGETS)

install:
	install -d $(DESTDIR)$(PREFIX)/bin/ 
	install -D $(TARGETS) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(foreach t,$(TARGETS),$(DESTDIR)$(PREFIX)/bin/$(t))
