# XDP-TCPDUMP

xdp-tcpdump is tcpdump like tool for eXpress Data Path (XDP).

# Installation

## Environment

### clang

```
curl -LO http://releases.llvm.org/7.0.1/llvm-7.0.1.src.tar.xz
tar -xf llvm-7.0.1.src.tar.xz
mkdir llvm-build
cd llvm-build
cmake3 -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release ../llvm-7.0.1.src
  make -j`cat /proc/cpuinfo | grep processor -c`
  make install
```

### llvm

```
curl -LO http://releases.llvm.org/7.0.1/cfe-7.0.1.src.tar.xz
tar -xf cfe-7.0.1.src.tar.xz
mkdir clang-build
cd clang-build
cmake3 -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release ../cfe-7.0.1.src
  make -j`cat /proc/cpuinfo | grep processor -c`
  sudo make install
```

### check llvm

```
$llc --version
```

```
LLVM (http://llvm.org/):
  LLVM version 7.0.1
  Optimized build.
  Default target: x86_64-unknown-linux-gnu
  Host CPU: skylake

  Registered Targets:
    bpf    - BPF (host endian)
    bpfeb  - BPF (big endian)
    bpfel  - BPF (little endian)
    x86    - 32-bit X86: Pentium-Pro and above
    x86-64 - 64-bit X86: EM64T and AMD64
```

### libbpf.a

(maybe you need install follow first, and make sure that you have kernel source code in `/lib/modules/`uname -r`/`)

```
dnf install binutils-devel
or
yum install binutils-devel
```

```
dnf install readline-devel
or
yum install readline-devel
```

```
make -C /lib/modules/`uname -r`/source/tools
```

## Build and Install

```
./configure

make

make install
```

# Usage

* Capture tcp packet which come from network interface lo `xdp-tcpdump -i lo tcp`. (default capture from network interface which index is 0)

* Specifies dst port 80 and dst host 127.0.0.1 `xdp-tcpdump -i lo tcp --dst_port 80 --dst_addr 127.0.0.1`.
