.PHONY: all clean

PREFIX	?= arm-none-eabi
CC		= $(PREFIX)-gcc
LD		= $(PREFIX)-gcc
OBJCOPY	= $(PREFIX)-objcopy
OBJDUMP	= $(PREFIX)-objdump
GDB		= $(PREFIX)-gdb

OPENCM3DIR = ./libopencm3
ARMNONEEABIDIR = /usr/arm-none-eabi
COMMONDIR = ./common

ARCH_FLAGS = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16

LIB_BLAKE2s=blake2s-opt-bin/lib/blake2s.lib
LIB_MBED_CRYPTO=mbedtls/library/libmbedcrypto.a

all: htmac_aes_benchmark.bin \
	pmac_aes_benchmark.bin \
	aes_gcm_siv_benchmark_128.bin \
	aes_gcm_benchmark_128.bin \
	aes_obc_benchmark.bin \
	aes_obc_siv_benchmark.bin \
	jolteon_aes_benchmark_128.bin \
	espeon_aes_benchmark_128.bin

%.elf: LDSCRIPT = $(COMMONDIR)/stm32f407x6.ld
%.elf: LDFLAGS += -lopencm3_stm32f4
%.elf: OBJS += $(COMMONDIR)/stm32f4_wrapper.o

CFLAGS		+= -std=c99 -O3 -fomit-frame-pointer\
		   -Wall -Wextra -Wimplicit-function-declaration \
		   -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		   -Wundef -Wshadow \
		   -I$(ARMNONEEABIDIR)/include -I$(OPENCM3DIR)/include \
			 -Imbedtls/include \
			 -Iblake2s-opt-bin/include \
		   -fno-common $(ARCH_FLAGS) -MD \
			 -DSTM32F4 -DAES_ASSEMBLY
LDFLAGS		+= --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
		   -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections,--no-print-gc-sections \
		   $(ARCH_FLAGS) -L$(OPENCM3DIR)/lib

OBJS=aes/aes.o aes/aes.s aes/ghash.o aes/polyval.o aes/aes_gcm.o aes/aes_gcm_siv.o \
	aes-obc/aes_obc.o \
	aes-obc/aes_obc_siv.o \
	aes-modes/aes_modes.o \
	eevee-forkskinny/eevee_common.o eevee-forkskinny/espeon.o eevee-forkskinny/jolteon.o \
	aes/aes_xex_fork.o aes/jolteon_aes.o aes/espeon_aes.o

LIBS=${LIB_BLAKE2s} ${LIB_MBED_CRYPTO}

aes-modes/aes_modes.o: aes-modes/aes_modes.c
	${CC} ${CFLAGS} -c -o aes-modes/aes_modes.o aes-modes/aes_modes.c

aes-obc/aes_obc.o: aes-obc/aes_obc.c
	${CC} ${CFLAGS} -c -o aes-obc/aes_obc.o aes-obc/aes_obc.c

aes-obc/aes_obc_siv.o: aes-obc/aes_obc_siv.c
	${CC} ${CFLAGS} -c -o aes-obc/aes_obc_siv.o aes-obc/aes_obc_siv.c

eevee-forkskinny/jolteon.o: eevee-forkskinny/jolteon.h eevee-forkskinny/eevee_common.h eevee-forkskinny/jolteon_core.c eevee-forkskinny/jolteon.c
	${CC} ${CFLAGS} -D${FORKSKINNY_BACKEND} -c -o eevee-forkskinny/jolteon.o eevee-forkskinny/jolteon.c

eevee-forkskinny/espeon.o: eevee-forkskinny/espeon.h eevee-forkskinny/eevee_common.h eevee-forkskinny/espeon.c
	${CC} ${CFLAGS} -D${FORKSKINNY_BACKEND} -c -o eevee-forkskinny/espeon.o eevee-forkskinny/espeon.c




${LIB_BLAKE2s}: blake2s-opt/
	mkdir -p blake2s-opt-bin
	cd blake2s-opt && \
	CC=${CC} CFLAGS="${CFLAGS} -I../${OPENCM3DIR}/include" ./configure --prefix=../blake2s-opt-bin --generic && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) lib && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) install-lib

${LIB_MBED_CRYPTO}: mbedtls/
	cd mbedtls && \
	CC=${CC} CFLAGS="${CFLAGS}" $(MAKE) library/libmbedcrypto.a

%.bin: %.elf
	$(OBJCOPY) -Obinary $^ $@

%.elf: %.o $(OBJS) $(COMMONDIR)/stm32f4_wrapper.o $(LDSCRIPT) ${LIBS}
	$(LD) -o $@ $< $(OBJS) $(LDFLAGS) ${LIBS}
%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f *.o *.d *.elf *.bin aes/*.o aes/*.d aes-modes/*.o aes_modes/*.d aes-obc/*.o aes-obc/*.d
	rm -rf blake2s-opt-bin/
	cd mimc-gmp && $(MAKE) -f cortex-m4.mk clean
	cd mbedtls && $(MAKE) clean

deepclean: clean
	rm -rf gmp-6.2.1-bin32/
	cd gmp-6.2.1-32bit && $(MAKE) clean
