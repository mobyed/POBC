# OBC
## Make sure clang++ has been installed
```bash
sudo apt upgrade
sudo apt install clang
```

## Pull MP-SPDZ submodule
```bash
git submodule update --init --recursive
```

## Navigate to MP-SPDZ directory and install all dependencies.
Refer to [MP-SPDZ/README](https://github.com/data61/MP-SPDZ/blob/cf51528de6248ddef1aef1e2a281b7a0a28f7f5b/README.md) and [MP-SPDZ online documentation](https://mp-spdz.readthedocs.io/en/latest/).

### Dependencies installed on server (Ubuntu 22.04.2 LTS)
```bash
sudo apt-get install automake build-essential cmake git \
libboost-dev libboost-thread-dev libntl-dev libsodium-dev \
libssl-dev libtool m4 python3 texinfo yasm htop python3-pip libgmp3-dev
```

## Configure USE_GF2N_LONG
```bash
echo "USE_GF2N_LONG = 1" > CONFIG.mine
```

## Configure Boost download address
```bash
echo 'url = "https://archives.boost.io/release/1.{0}.0/source/{1}".format(version, arch)' > deps/libOTe/cryptoTools/thirdparty/getBoost.py
```

## Compile Boost and libOTe
```bash
make boost libote
```

## Compile MASCOT protocol executable file
```bash
make -j mascot-party.x
```

## Replace run-script
```bash
cp -r ../code/Scripts/run-common.sh ./Scripts/run-common.sh
```

## Test and Run
- Now we can compile the bytecode for the benchmark. All modes can be compiled through the 
`bash
benchmark
`
 file where the arguments give details about the mode, the SIMD factor(default: 1) and the message length. For example:
`bash
$> ./compile.py benchmark aes_obc64 1 16
`
- This creates 
`bash
Programs/Schedules/benchmark-aes_obc64-1-16.sch
`
 and 
`bash
Programs/Bytecode/benchmark-aes_obc64-1-16.bc
`
- The following circuits are available
    * AES-GCM  `aes_gcm64`
    * AES-OBC  `aes_obc64`
    * AES-GCM-SIV  `aes_gcm_siv64`
    * AES-OBC-SIV  `aes_obc_siv`
    * AES-CTR-PMAC  `pmac_aes64`
    * ForkAES-Jolteon `jolteon_forkaes64`(cite from [Eevee](https://github.com/KULeuven-COSIC/Eevee))
    * ForkAES-Espeon `espeon_forkaes64`(cite from [Eevee](https://github.com/KULeuven-COSIC/Eevee))
      
Note that the benchmark just decrypts a random/zero ciphertext with a random/zero key and Eevee family need to add manually in benchmark.

- In order to test the function, MPC protocol can run locally, for example, each MPC party runs on a local PC and communicates through a local host. MP-SPDZ has provided useful scripts for this.
  (In the MP-SPDZ directory) Use ` Scripts/mascot.sh -v --batch-size 64 benchmark-aes_obc64-1-16 ` to run the previously compiled benchmark. Option ` -v ` gives more detailed information about executing and reporting timing data. And option ` --batch-size ` gives a more accurate test result.
