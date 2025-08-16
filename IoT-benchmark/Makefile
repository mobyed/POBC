CC=gcc
CFLAGS=-std=c99 -pedantic -Wall -Wextra -Werror -fomit-frame-pointer -Iblake2s-opt-bin/include  -Imbedtls/include -O3
LIB_BLAKE2s=blake2s-opt-bin/lib/blake2s.lib
LIB_MBED_CRYPTO=mbedtls/library/libmbedcrypto.a

LDFLAGS= -L mbedtls/library/ -l mbedcrypto -lcrypto

OBJS=aes/aes.o aes/ghash.o aes/polyval.o aes/aes_gcm.o aes/aes_gcm_siv.o \
	aes-obc/aes_obc.o aes-obc/aes_obc_siv.o \
	aes-modes/aes_modes.o
LIBS=${LIB_BLAKE2s} ${LIB_MBED_CRYPTO}

.PHONY: clean deepclean

all: generate.x

generate.x: generate.c ${OBJS} ${LIBS}
	${CC} ${CFLAGS} -o generate.x generate.c ${GENERATE_X_OBJS} ${OBJS} -lm ${LDFLAGS}  ${LIB_BLAKE2s}

aes-obc/aes_obc.o: aes-obc/aes_obc.c aes-obc/aes_obc.h
	$(CC) $(CFLAGS) -c -o aes-obc/aes_obc.o aes-obc/aes_obc.c

aes-obc/aes_obc_siv.o: aes-obc/aes_obc_siv.c aes-obc/aes_obc_siv.h
	$(CC) $(CFLAGS) -c -o aes-obc/aes_obc_siv.o aes-obc/aes_obc_siv.c

aes-modes/aes_modes.o: aes-modes/aes_modes.c aes-modes/aes_modes.h
	$(CC) $(CFLAGS) -c -o aes-modes/aes_modes.o aes-modes/aes_modes.c


${LIB_BLAKE2s}: blake2s-opt/
	mkdir -p blake2s-opt-bin
	cd blake2s-opt && \
	CC=${CC} CFLAGS="${CFLAGS}" ./configure --prefix=../blake2s-opt-bin --generic && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) lib && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) install-lib

${LIB_MBED_CRYPTO}: mbedtls/
	cd mbedtls && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) library/libmbedcrypto.a

clean:
	rm -f *.o *.x aes/*.o aes-obc/*.o aes-modes/*.o
	rm -rf blake2s-opt-bin/
	cd mbedtls && $(MAKE) clean

deepclean: clean
	rm -rf gmp-6.2.1-bin64/
	cd gmp-6.2.1-64bit && $(MAKE) clean
