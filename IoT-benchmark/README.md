## IoT Benchmark
### Hardware Setup
We use the STM32F407G-DISC1 board that runs the benchmark code. The timing results (cycles) are communicated back to the PC via a Serial-to-USB converter (CP2102 USB UART Board MINI). The following pins are connected:

| Cortex-M4 (STM32F407G-DISC1) | Serial-to-USB (CP2102 USB UART Board MINI) |
| ---------------------------- | ------------------------------------------ |
| GND                          | GND                                        |
| PA2                          | RXD                                        |
| PA3                          | TXD                                        |

The Serial-to-USB converter is then connected via USB to the PC. If the pins of the microcontroller are different, this change has to be reflected in the benchmark source code (e.g. `aes_pobc_benchmark.c`).

### Build
```bash
sudo apt-get install gcc-arm-none-eabi
git submodule update --init --recursive
cd libopencm3
make
cd ..
make generate.x
make -f cortex-m4.mk clean
make -f cortex-m4.mk all
```

After finishing the above steps, several `.bin` files created in this folder, which can be uploaded to the hardware device (We used [STM32CubeProgrammer](https://www.st.com/en/development-tools/stm32cubeprog.html) to upload).

### Executables

- `generate.x` outputs test vectors for a selected mode of a given length. These are sent to the device with `run-experiment.py`.
	For example, you can run
	
	```bash
	./generate.x aes_pobc 32 1000 > aes_pobc_32bytes_1000
	```
  
  to output 1000 samples of 32 bytes message/ciphertext pairs, encrypted by AES-POBC.
  
- `run-experiment.py` Given a file with test vectors in the format of `generate.x`, sends a test vector (key, nonce, message) to the connected M4, receives ciphertext, tag and the cycle count. In the end, the script saves all cyclecounts and computes an average cyclecount.
	
	For example, you can run
	
	```bash
	python run-exeriment.py --samples aes_pobc_32bytes_1000 -o aes_pobc_32bytes_1000_cycles
	```
	
	to test encryption performance of different algorithms in Cortex-M4 device (relative `.bin` files must be uploaded to device before test an corresponding algorithm), then the total cycles will output in the terminal.

### Modes Provided
- **AES-POBC** with instantiation `AES-128` in `aes-pobc/aes_pobc.h, aes-pobc/aes_pobc.c`
- **AES-POBC-SIV** with instantiation `AES-128` in `aes-pobc/aes_pobc_siv.h, aes-pobc/aes_pobc_siv.c`
- **AES-GCM** with instantiation `AES-128` in `aes/aes_gcm.h, aes/aes_gcm.c`
- **AES-GCM-SIV** with instantiation `AES-128` in `aes/aes_gcm_siv.h, aes/aes_gcm_siv.c`
- **AES-CTR-PMAC** with instantiation `AES-128` in `aes-modes/aes_modes.h, aes-modes/aes_modes.c`
- **ForkAES-Jolteon** with instantiation `AES-128` in `eevee-forkskinny/espeon.h, eevee-forkskinny/espeon.c` (cite from [Eevee](https://github.com/KULeuven-COSIC/Eevee))
- **ForkAES-Espeon** with instantiation `AES-128` in `eevee-forkskinny\jolteon.h, eevee-forkskinny\jolteon.c` (cite from [Eevee](https://github.com/KULeuven-COSIC/Eevee))

### IoT Benchmark results
The folder `vectors` contains test vectors and the folder `results` contains the queried the corresponding reported cycle count. We tested 1000 samples each of lengths 8, 16, 32, 64, 128, 256, 512 and 1024bytes.

