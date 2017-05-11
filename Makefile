### User defined variables ######################################################
DEBUG := y
WOLFSSL_ARCHIVE := wolfssl-3.9.10.tar.gz
WOLFSSL_URL := http://www.wolfssl.com/$(WOLFSSL_ARCHIVE)

### Should not need to change below this line ###################################
BIN         := mb
PWD         := $(shell pwd)
USR_DIR	    := $(PWD)/usr
DEP_DIR     := $(PWD)/deps
CFLAGS      += -Wall -Wno-parentheses -Wno-switch-enum -Wno-unused-value
LIBS        := -L$(USR_DIR)/lib -lpthread -lm -Wl,-Bstatic -lwolfssl -Wl,-Bdynamic
VERSION_H   := version.h
GIT_VERSION := $(shell git rev-parse --short=6 HEAD 2>/dev/null)

ifeq ($(DEBUG),y)
CFLAGS  += -g
endif

ifeq ($(GIT_VERSION),)
VERSION := 0.1
else
VERSION := $(GIT_VERSION)
endif

WOLFSSL_DIR := wolfssl
WOLFSSL_LIB := libwolfssl.a
CFLAGS  += -I$(USR_DIR)/include -DHAVE_SNI -DHAVE_SECURE_RENEGOTIATION

SRC := $(wildcard src/*.c)
OBJ := ${SRC:.c=.o}

LIBAE_SRC = libae/ae.c libae/anet.c
LIBAE_OBJ = ${LIBAE_SRC:.c=.o}
LIBAE_LIB = libae/libae.a

LIBJSON_SRC = json/json.c
LIBJSON_OBJ = ${LIBJSON_SRC:.c=.o}
LIBJSON_LIB = json/libjson.a

all: deps $(BIN)

deps: $(LIBAE_LIB) $(LIBJSON_LIB) $(USR_DIR)/lib/$(WOLFSSL_LIB) 

$(DEP_DIR)/$(WOLFSSL_ARCHIVE):
	curl --create-dirs -Ls $(WOLFSSL_URL) -o "$(DEP_DIR)/$(WOLFSSL_ARCHIVE)"

$(USR_DIR)/lib/$(WOLFSSL_LIB): $(DEP_DIR)/$(WOLFSSL_ARCHIVE)
	mkdir -p $(WOLFSSL_DIR)
	tar zxvf $(DEP_DIR)/$(WOLFSSL_ARCHIVE) --strip=1 -C $(WOLFSSL_DIR)
	(cd $(WOLFSSL_DIR) && \
	  ./configure \
	    --enable-sni \
	    --enable-static \
	    --enable-fastmath \
	    --enable-sslv3 \
	    --enable-aesni \
	    --enable-hugecache \
	    --enable-intelasm \
	    --enable-secure-renegotiation \
	    --enable-truncatedhmac && \
	  make install prefix=$(USR_DIR))

$(LIBAE_LIB): $(LIBAE_OBJ)
	$(AR) -rc $@ $(LIBAE_OBJ)

$(LIBJSON_LIB): $(LIBJSON_OBJ)
	$(AR) -rc $@ $(LIBJSON_OBJ)

%.o: %.c %.h $(VERSION_H)
	$(CC) $(CFLAGS) -c $< -o $@

$(VERSION_H):
	@echo "#define MB_VERSION \"$(VERSION)\"" > $(VERSION_H)

$(BIN): nginx/http_parser.o $(OBJ) libae/libae.a json/libjson.a
	$(CC) $^ $(LIBS) -o $@

clean:
	rm -f $(BIN) $(OBJ) libae/*.o libae/*.a json/*.o json/*.a nginx/*.o $(VERSION_H)

distclean: clean
	rm -rf $(USR_DIR) $(DEP_DIR) $(WOLFSSL_DIR)

.PHONY: clean distclean
