# OBC
##make sure "sudo apt upgrade / sudo apt install clang"
##Pull the MP-SPDZ submodule: git submodule update --init --recursive
##Navigate into the MP-SPDZ folder and install all dependencies (cf MP-SPDZ/REAMDE and MP-SPDZ online documentation)
###on our servers (Ubuntu 22.04.2 LTS), we installed apt-get install automake build-essential cmake git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm htop python3-pip libgmp3-dev 
###configure USE_GF2N_LONG: echo "USE_GF2N_LONG = 1" > CONFIG.mine
###configure echo "url = "https://archives.boost.io/release/1.{0}.0/source/{1}".format(version, arch)" > deps\libOTe\cryptoTools\thirdparty\getBoost.py
###make boost libote
###make mascot-party.x

###./Scripts/run-common.sh
