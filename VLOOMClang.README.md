## Build LLVM from source

Reference  https://llvm.org/docs/CMake.html, https://llvm.org/docs/GettingStarted.html, and https://llvm.org/docs/GoldPlugin.html

#### 1. Build debug version
```shell
$ mkdir build_debug
$ cd build_debug
#The default build type is "Debug"
$ cmake path/to/llvm/source/root  -DCMAKE_BUILD_TYPE=Debug
$ cmake --build .
$ cmake -DCMAKE_INSTALL_PREFIX=~/vloom-vcfi/llvm-debug  -P cmake_install.cmake
```

#### 2. Build release version
```shell
$ mkdir build_release
$ cd build_release
$ cmake path/to/llvm/source/root  -DCMAKE_BUILD_TYPE=Release
$ cmake --build .
$ cmake -DCMAKE_INSTALL_PREFIX=~/vloom-vcfi/llvm-release -P cmake_install.cmake
```

#### 3. Build release version with llvm-gold plugin

1. Download the plugin-api.h
```shell
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
```

2. Build VLOOMClang
```shell
$ mkdir build_release_gold
$ cd build_release_gold
#Double check if DLLVM_BINUTILS_INCDIR contains file plugin-api.h
$ cmake path/to/llvm/source/root -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=/path/to/binutils/include
$ cmake --build .
$ cmake -DCMAKE_INSTALL_PREFIX=~/vloom-vcfi/llvm-release-gold -P cmake_install.cmake
```