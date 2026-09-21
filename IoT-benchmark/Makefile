CC=gcc
CFLAGS=-std=c99 -pedantic -Wall -Wextra -Werror -fomit-frame-pointer -Iblake2s-opt-bin/include  -Imbedtls/include -O3
LIB_BLAKE2s=blake2s-opt-bin/lib/blake2s.lib
LIB_MBED_CRYPTO=mbedtls/library/libmbedcrypto.a

LDFLAGS= -L mbedtls/library/ -l mbedcrypto -lcrypto

OBJS=aes/aes.o aes/ghash.o aes/polyval.o aes/aes_gcm.o aes/aes_gcm_siv.o \
	aes-pobc/aes_pobc.o aes-pobc/aes_pobc_siv.o \
	aes-modes/aes_modes.o \
	eevee-forkskinny/espeon.o eevee-forkskinny/jolteon.o \
	aes/jolteon_aes.o aes/espeon_aes.o
LIBS=${LIB_BLAKE2s} ${LIB_MBED_CRYPTO}

.PHONY: clean deepclean

all: generate.x

generate.x: generate.c ${OBJS} ${LIBS}
	${CC} ${CFLAGS} -o generate.x generate.c ${GENERATE_X_OBJS} ${OBJS} -lm ${LDFLAGS}  ${LIB_BLAKE2s}

aes-pobc/aes_pobc.o: aes-pobc/aes_pobc.c aes-pobc/aes_pobc.h
	$(CC) $(CFLAGS) -c -o aes-pobc/aes_pobc.o aes-pobc/aes_pobc.c

aes-pobc/aes_pobc_siv.o: aes-pobc/aes_pobc_siv.c aes-pobc/aes_pobc_siv.h
	$(CC) $(CFLAGS) -c -o aes-pobc/aes_pobc_siv.o aes-pobc/aes_pobc_siv.c

aes-modes/aes_modes.o: aes-modes/aes_modes.c aes-modes/aes_modes.h
	$(CC) $(CFLAGS) -c -o aes-modes/aes_modes.o aes-modes/aes_modes.c

eevee-forkskinny/jolteon.o: eevee-forkskinny/jolteon.h eevee-forkskinny/eevee_common.h eevee-forkskinny/jolteon_core.c eevee-forkskinny/jolteon.c
	${CC} ${CFLAGS} -D${FORKSKINNY_BACKEND} -c -o eevee-forkskinny/jolteon.o eevee-forkskinny/jolteon.c

eevee-forkskinny/espeon.o: eevee-forkskinny/espeon.h eevee-forkskinny/eevee_common.h eevee-forkskinny/espeon.c
	${CC} ${CFLAGS} -D${FORKSKINNY_BACKEND} -c -o eevee-forkskinny/espeon.o eevee-forkskinny/espeon.c

eevee-forkskinny/eevee_common.o: eevee-forkskinny/eevee_common.h eevee-forkskinny/eevee_common.c
	${CC} ${CFLAGS} -D${FORKSKINNY_BACKEND} -c -o eevee-forkskinny/eevee_common.o eevee-forkskinny/eevee_common.c


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
	rm -f *.o *.x aes/*.o aes-pobc/*.o aes-modes/*.o
	rm -rf blake2s-opt-bin/
	cd mbedtls && $(MAKE) clean

deepclean: clean
	rm -rf gmp-6.2.1-bin64/
	cd gmp-6.2.1-64bit && $(MAKE) clean
