### User defined variables ######################################################
DEBUG := y
SSL_ENABLE := y

### Should not need to change below this line ###################################
BIN         := mb
PWD         := $(shell pwd)
USR_DIR	    := $(PWD)/usr
DEP_DIR     := $(PWD)/deps
CFLAGS      += -Wall -Wno-parentheses -Wno-switch-enum -Wno-unused-value -Wno-error
LIBS        := -L$(USR_DIR)/lib -lpthread -lm
VERSION_H   := version.h
GIT_VERSION := $(shell git describe 2>/dev/null || git rev-parse --short=6 HEAD 2>/dev/null)

ifeq ($(DEBUG),y)
CFLAGS  += -g
endif

ifeq ($(SSL_ENABLE),y)
CFLAGS += -DHAVE_SSL
WOLFSSL_ARCHIVE := v3.12.2-stable.tar.gz
WOLFSSL_URL := https://github.com/wolfSSL/wolfssl/archive/$(WOLFSSL_ARCHIVE)
WOLFSSL_DIR := wolfssl
WOLFSSL_LIB := $(USR_DIR)/lib/libwolfssl.a
CFLAGS += -I$(USR_DIR)/include
LIBS += -Wl,-Bstatic -lwolfssl -Wl,-Bdynamic
endif

SRC := $(wildcard src/*.c)
OBJ := ${SRC:.c=.o}

LIBAE_SRC = libae/ae.c libae/anet.c
LIBAE_OBJ = ${LIBAE_SRC:.c=.o}
LIBAE_LIB = libae/libae.a

LIBJSON_SRC = json/json.c
LIBJSON_OBJ = ${LIBJSON_SRC:.c=.o}
LIBJSON_LIB = json/libjson.a

all: deps $(BIN)

deps: $(WOLFSSL_LIB) $(LIBAE_LIB) $(LIBJSON_LIB) 

$(DEP_DIR)/$(WOLFSSL_ARCHIVE):
	curl --create-dirs -Ls $(WOLFSSL_URL) -o "$(DEP_DIR)/$(WOLFSSL_ARCHIVE)"

$(WOLFSSL_LIB): $(DEP_DIR)/$(WOLFSSL_ARCHIVE)
	mkdir -p $(WOLFSSL_DIR)
	tar zxvf $(DEP_DIR)/$(WOLFSSL_ARCHIVE) --strip=1 -C $(WOLFSSL_DIR)
	(cd $(WOLFSSL_DIR) && \
	  mkdir -p .git && \
	  ./autogen.sh && \
	  ./configure CFLAGS="-Wno-stringop-truncation -Wno-stringop-overflow -Wno-size-of-pointer-memaccess" \
	    --disable-examples \
	    --enable-aesni \
	    --enable-fastmath \
	    --enable-hugecache \
	    --enable-intelasm \
	    --enable-oldtls \
	    --enable-secure-renegotiation \
	    --enable-session-ticket \
	    --enable-sni \
	    --enable-sslv3 \
	    --enable-static \
	    --enable-tlsv10 \
	    --enable-truncatedhmac && \
	  make install prefix=$(USR_DIR))

$(LIBAE_LIB): $(LIBAE_OBJ)
	$(AR) -rc $@ $(LIBAE_OBJ)

$(LIBJSON_LIB): $(LIBJSON_OBJ)
	$(AR) -rc $@ $(LIBJSON_OBJ)

%.o: %.c %.h $(VERSION_H) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

$(VERSION_H):
	@echo "#define MB_VERSION \"$(GIT_VERSION)\"" > $(VERSION_H)

$(BIN): nginx/http_parser.o $(OBJ) libae/libae.a json/libjson.a
	$(CC) $^ $(LIBS) -o $@

clean:
	rm -f $(BIN) $(OBJ) libae/*.o libae/*.a json/*.o json/*.a nginx/*.o $(VERSION_H)

distclean: clean
	rm -rf $(USR_DIR) $(DEP_DIR) $(WOLFSSL_DIR)

.PHONY: clean distclean
