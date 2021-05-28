#### 1. Build debug version

mkdir build_debug
cd build_debug
#The default build type is "Debug"
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build .
cmake -DCMAKE_INSTALL_PREFIX=/home/yph/Projects/vloom-vcfi/llvm-debug  -P cmake_install.cmake

#### 2. Build release version

mkdir build_release
cd build_release
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build .
cmake -DCMAKE_INSTALL_PREFIX=/home/yph/Projects/vloom-vcfi/llvm-release -P cmake_install.cmake

#### 3. Build release version with llvm-gold plugin
cd /home/yph/Projects/vloom-vcfi
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils

mkdir build_release_gold
cd build_release_gold
#Double check if DLLVM_BINUTILS_INCDIR contains file plugin-api.h
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=/home/yph/Projects/vloom-vcfi/binutils/include
cmake --build .
cmake -DCMAKE_INSTALL_PREFIX=/home/yph/Projects/vloom-vcfi/llvm-release-gold -P cmake_install.cmake
