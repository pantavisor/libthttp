#TARGETS = thttp-example1 thttp-example1-tls trest-example1 trest-example1-tls trail-example1 libtrail.a
TARGETS = libtrail.a

DEBUG := 0
CFLAGS := -g 

trest-example1_DEFINES := -DJSMN_PARENT_LINKS=1 -DDEBUG=$(DEBUG)
trest-example1-tls_DEFINES := -DJSMN_PARENT_LINKS=1 -DDEBUG=$(DEBUG)

thttp-example1_DEFINES := -DDEBUG=$(DEBUG)
thttp-example1-tls_DEFINES := -DDEBUG=$(DEBUG)

trail-example1_DEFINES := -DDEBUG=$(DEBUG)

OBJDIR := $(BUILDDIR)

MBEDTLS_DIR := mbedtls-2.3.0
MBEDTLS_LIBS := \
	libmbedtls.a \
	libmbedx509.a \
	libmbedcrypto.a \
	$(NULL)
MBEDTLS_PROFILE := config-mini-tls1_1

MBEDTLS_CFLAGS := -I$(MBEDTLS_DIR)/configs/ \
	-I$(MBEDTLS_DIR)/include/ \
	-DMBEDTLS_CONFIG_FILE='<$(MBEDTLS_PROFILE).h>' \
	$(NULL)
MBEDTLS_LDFLAGS := $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))

all: $(TARGETS)

LIBTHTTP_PREREQ := \
	thttp.c thttp.h \
	tinyhttp/chunk.c tinyhttp/chunk.h \
	tinyhttp/header.c tinyhttp/header.h \
	tinyhttp/http.c tinyhttp/http.h \
	jsmn/jsmnutil.c jsmn/jsmnutil.h \
	jsmn/jsmn.c jsmn/jsmn.h \
	$(NULL)

LIBTREST_PREREQ := \
	$(LIBTHTTP_PREREQ) \
	trest.c trest.h \

LIBTRAIL_PREREQ := \
	$(LIBTREST_PREREQ) \
	trail.c trail.h \

V := 1
MAKEFLAGS += -V=1

LIBTRAIL_SRCS := $(filter %.c, $(LIBTRAIL_PREREQ))
LIBTRAIL_OBJS := $(addprefix $(OBJDIR)/, $(LIBTRAIL_SRCS:.c=.o))

$(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l)):
	CFLAGS="-I$(PWD)/$(MBEDTLS_DIR)/configs/ -DMBEDTLS_CONFIG_FILE='<$(MBEDTLS_PROFILE).h>'" \
		make -C $(MBEDTLS_DIR)/library $(MAKEFLAGS) $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))

thttp-example1: $(LIBTHTTP_PREREQ) thttp-example1.c $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) -o $(OBJDIR)/$@ \
		$(filter %.c, $^) $(MBEDTLS_LDFLAGS)

thttp-example1-tls: $(LIBTHTTP_PREREQ) thttp-example1-tls.c $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) -o $@ \
		$(filter %.c, $^) $(MBEDTLS_LDFLAGS)

trest-example1: $(LIBTREST_PREREQ) trest-example1.c $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) $($@_DEFINES) -o $@ \
		$(filter %.c, $^) $(MBEDTLS_LDFLAGS)

trest-example1-tls: $(LIBTREST_PREREQ) trest-example1-tls.c $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) $($@_DEFINES) -o $@ \
		$(filter %.c, $^) $(MBEDTLS_LDFLAGS)

trail-example1: $(LIBTRAIL_PREREQ) trail-example1.c $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) $($@_DEFINES) -o $@ \
		$(filter %.c, $^) $(MBEDTLS_LDFLAGS)

$(OBJDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) $($@_DEFINES) -c $< -o $@

libtrail.a: $(LIBTRAIL_OBJS) $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l))
	echo $^
	$(AR) rcs $(OBJDIR)/$@ $^

clean:
	make -C $(MBEDTLS_DIR)/library clean $(MAKEFLAGS)
	rm -f $(addprefix $(OBJDIR)/, $(TARGETS)) $(LIBTRAIL_OBJS) $(foreach l, $(MBEDTLS_LIBS), $(OBJDIR)/$(l)) $(OBJDIR)/mbedtls/*.o

#install:
#	install -d $(DESTDIR)$(PREFIX)/bin
#	install -D $(TARGETS) $(DESTDIR)$(PREFIX)/bin/

install:
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/usr/include/jsmn
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/usr/include/mbedtls
	install -D $(OBJDIR)/libtrail.a $(DESTDIR)$(PREFIX)/lib/
	install -D $(OBJDIR)/libmbed*.a $(DESTDIR)$(PREFIX)/lib/
	install -D trail.h $(DESTDIR)$(PREFIX)/usr/include/
	install -D trest.h $(DESTDIR)$(PREFIX)/usr/include/
	install -D thttp.h $(DESTDIR)$(PREFIX)/usr/include/
	install -D thttp-enums.h $(DESTDIR)$(PREFIX)/usr/include/
	install -D jsmn/jsmn.h $(DESTDIR)$(PREFIX)/usr/include/jsmn/
	install -D jsmn/jsmnutil.h $(DESTDIR)$(PREFIX)/usr/include/jsmn/
	install -D mbedtls-2.3.0/include/mbedtls/sha256.h $(DESTDIR)$(PREFIX)/usr/include/mbedtls/

uninstall:
	rm -f $(foreach t,$(TARGETS),$(DESTDIR)$(PREFIX)/bin/$(t))
