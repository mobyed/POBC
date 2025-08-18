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
参考 `MP-SPDZ/README` 和 MP-SPDZ 在线文档

### 在我们的服务器（Ubuntu 22.04.2 LTS）上安装的依赖
```bash
sudo apt-get install automake build-essential cmake git \
libboost-dev libboost-thread-dev libntl-dev libsodium-dev \
libssl-dev libtool m4 python3 texinfo yasm htop python3-pip libgmp3-dev
```

## 配置 USE_GF2N_LONG
```bash
echo "USE_GF2N_LONG = 1" > CONFIG.mine
```

## 配置 Boost 下载地址
```bash
echo 'url = "https://archives.boost.io/release/1.{0}.0/source/{1}".format(version, arch)' > deps/libOTe/cryptoTools/thirdparty/getBoost.py
```

## 编译 Boost 和 libOTe
```bash
make boost libote
```

## 编译 MASCOT 协议可执行文件
```bash
make -j mascot-party.x
```

## 替换运行脚本
```bash
cp -r ../code/Scripts/run-common.sh ./Scripts/run-common.sh
```
