# gift-cofb
GIFT-COFB: Lightweight Authenticated Encryption

## Overview

GIFT-COFB is the 8th NIST Light Weight Cryptography (LWC) standardization effort's final round candidate, that I've picked up for implementation, as a zero-dependency, header-only, easy-to-use C++ library. GIFT-COFB AEAD offers one authenticated encryption with associated data algorithm, where associated data is never encrypted but it's integrity is ensured.

> Learn more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

GIFT-COFB AEAD has following two routines, which are implemented in this library

`encrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, this algorithm encrypts M -bytes plain text and produces equilength cipher text bytes, while also computing 16 -bytes authentication tag, used for checking integrity of both associated data and cipher text ( i.e. during decryption phase ) | N, M >= 0.

> Avoid using same public message nonce, under same secret key, more than once.

> Monotonically incrementing nonce can be choice of use, which provides quite large nonce space of 2^128 possibilities.

`decrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data & M -bytes encrypted text, this routine decrypts cipher text back to equilength plain text bytes, while also checking integrity of both associated data and cipher text, using supplied authentication tag, producing a boolean verification flag, denoting status of authentication check.

> Before consuming decrypted bytes, ensure presence of truth value in boolean verification flag.

During implementation of GIFT-COFB AEAD, I followed GIFT-COFB specification ( as submitted to NIST LWC final round call ), which can be retrieved from [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf).

Other seven NIST LWC finalists, which I've worked on, can be found in linked repositories

- [Ascon](https://github.com/itzmeanjan/ascon)
- [TinyJambu](https://github.com/itzmeanjan/tinyjambu)
- [Xoodyak](https://github.com/itzmeanjan/xoodyak)
- [Sparkle](https://github.com/itzmeanjan/sparkle)
- [Photon-Beetle](https://github.com/itzmeanjan/photon-beetle)
- [ISAP](https://github.com/itzmeanjan/isap)
- [Romulus](https://github.com/itzmeanjan/romulus)

> Track progress of NIST LWC standardization effort [here](https://csrc.nist.gov/Projects/lightweight-cryptography).

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0

$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: aarch64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- System development utilities such as `make`, `cmake`

```bash
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For ensuring functional correctness of GIFT-COFB, you'll need to execute Known Answer Tests, which requires availability of `python3`, `wget` and `unzip`

```bash
$ python3 --version
Python 3.10.4
```

- Python dependencies can be download using `pip`

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmarking GIFT-COFB AEAD on CPU systems, you'll need to globally install `google-benchmark`; you may follow [this](https://github.com/google/benchmark/tree/60b16f1#installation) guide.

## Testing

For ensuring functional correctness of GIFT-COFB AEAD implementation, I make use of Known Answer Tests provided along with NIST LWC final round submission package of GIFT-COFB.

Given 16 -bytes secret key, 16 -bytes public message nonce, plain text and associated data, I use GIFT-COFB `encrypt` routine for computing cipher text and 16 -bytes authentication tag, which is byte-by-byte compared against KATs. Finally an attempt to `decrypt` back to plain text, using GIFT-COFB verified decryption algorithm, is also made, which ensuring presence of truth value in boolean verification flag.

For executing tests, issue

```bash
make
```

## Benchmarking

For benchmarking GIFT-COFB encrypt/ decrypt routines, on CPU systems, issue

```bash
make benchmark
```

> For disabling CPU scaling issue, see [this](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

> Notice, GIFT-COFB encrypt/ decrypt routine's byte bandwidth is close to what underlying GIFT-128 block cipher offers ( see `gift_permute` row in benchmark table ), because COFB mode is rate-1 design i.e. every message block is processed only once & they are processed in 16 -bytes chunks which is also the width of underlying block cipher.

### On AWS Graviton3

```bash
2022-07-18T08:53:46+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.00, 0.00, 0.00
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        38.7 ns         38.7 ns     18096719 bytes_per_second=394.154M/s
bench_gift_cofb::gift_permute<2>        77.0 ns         77.0 ns      9097376 bytes_per_second=198.279M/s
bench_gift_cofb::gift_permute<3>         115 ns          115 ns      6067760 bytes_per_second=132.277M/s
bench_gift_cofb::gift_permute<4>         153 ns          153 ns      4571276 bytes_per_second=99.6389M/s
bench_gift_cofb::gift_permute<40>       1533 ns         1533 ns       457166 bytes_per_second=9.95102M/s
bench_gift_cofb::encrypt/32/64         10923 ns        10923 ns        64074 bytes_per_second=8.38165M/s
bench_gift_cofb::decrypt/32/64         10896 ns        10896 ns        64259 bytes_per_second=8.40228M/s
bench_gift_cofb::encrypt/32/128        17145 ns        17145 ns        40833 bytes_per_second=8.89981M/s
bench_gift_cofb::decrypt/32/128        17092 ns        17092 ns        41004 bytes_per_second=8.92751M/s
bench_gift_cofb::encrypt/32/256        29581 ns        29581 ns        23663 bytes_per_second=9.28507M/s
bench_gift_cofb::decrypt/32/256        29478 ns        29476 ns        23757 bytes_per_second=9.31789M/s
bench_gift_cofb::encrypt/32/512        54462 ns        54461 ns        12854 bytes_per_second=9.52615M/s
bench_gift_cofb::decrypt/32/512        54235 ns        54234 ns        12923 bytes_per_second=9.5659M/s
bench_gift_cofb::encrypt/32/1024      104215 ns       104212 ns         6717 bytes_per_second=9.66376M/s
bench_gift_cofb::decrypt/32/1024      103752 ns       103750 ns         6756 bytes_per_second=9.70679M/s
bench_gift_cofb::encrypt/32/2048      203723 ns       203719 ns         3436 bytes_per_second=9.73715M/s
bench_gift_cofb::decrypt/32/2048      202750 ns       202746 ns         3453 bytes_per_second=9.78389M/s
bench_gift_cofb::encrypt/32/4096      402739 ns       402731 ns         1738 bytes_per_second=9.77517M/s
bench_gift_cofb::decrypt/32/4096      399705 ns       399695 ns         1751 bytes_per_second=9.84942M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-18T12:49:19+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.40, 2.09, 1.84
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        45.1 ns         44.6 ns     15585480 bytes_per_second=342.187M/s
bench_gift_cofb::gift_permute<2>        70.3 ns         70.2 ns      9743604 bytes_per_second=217.271M/s
bench_gift_cofb::gift_permute<3>         106 ns          106 ns      6573079 bytes_per_second=143.857M/s
bench_gift_cofb::gift_permute<4>         140 ns          140 ns      4918770 bytes_per_second=109.217M/s
bench_gift_cofb::gift_permute<40>       1400 ns         1399 ns       499216 bytes_per_second=10.904M/s
bench_gift_cofb::encrypt/32/64         10028 ns        10017 ns        69284 bytes_per_second=9.14014M/s
bench_gift_cofb::decrypt/32/64         10014 ns         9986 ns        68694 bytes_per_second=9.16826M/s
bench_gift_cofb::encrypt/32/128        15492 ns        15487 ns        44568 bytes_per_second=9.85272M/s
bench_gift_cofb::decrypt/32/128        15729 ns        15712 ns        43372 bytes_per_second=9.71183M/s
bench_gift_cofb::encrypt/32/256        27171 ns        27145 ns        25608 bytes_per_second=10.1183M/s
bench_gift_cofb::decrypt/32/256        27103 ns        27075 ns        26003 bytes_per_second=10.1443M/s
bench_gift_cofb::encrypt/32/512        49918 ns        49887 ns        13631 bytes_per_second=10.3994M/s
bench_gift_cofb::decrypt/32/512        50134 ns        50080 ns        13586 bytes_per_second=10.3593M/s
bench_gift_cofb::encrypt/32/1024      102383 ns       101101 ns         7239 bytes_per_second=9.9611M/s
bench_gift_cofb::decrypt/32/1024      100220 ns        99568 ns         6530 bytes_per_second=10.1145M/s
bench_gift_cofb::encrypt/32/2048      194196 ns       193164 ns         3479 bytes_per_second=10.2692M/s
bench_gift_cofb::decrypt/32/2048      196600 ns       195520 ns         3487 bytes_per_second=10.1455M/s
bench_gift_cofb::encrypt/32/4096      376573 ns       375136 ns         1799 bytes_per_second=10.4943M/s
bench_gift_cofb::decrypt/32/4096      372943 ns       372359 ns         1817 bytes_per_second=10.5725M/s
```

### On AWS Graviton2

```bash
2022-07-18T08:52:45+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.11, 0.03, 0.01
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        89.2 ns         89.2 ns      7842990 bytes_per_second=171.08M/s
bench_gift_cofb::gift_permute<2>         175 ns          175 ns      4002040 bytes_per_second=87.2417M/s
bench_gift_cofb::gift_permute<3>         260 ns          260 ns      2690410 bytes_per_second=58.6453M/s
bench_gift_cofb::gift_permute<4>         346 ns          346 ns      2021209 bytes_per_second=44.0592M/s
bench_gift_cofb::gift_permute<40>       3440 ns         3440 ns       203497 bytes_per_second=4.43588M/s
bench_gift_cofb::encrypt/32/64         24686 ns        24685 ns        28355 bytes_per_second=3.70879M/s
bench_gift_cofb::decrypt/32/64         24286 ns        24285 ns        28824 bytes_per_second=3.76988M/s
bench_gift_cofb::encrypt/32/128        38785 ns        38784 ns        18048 bytes_per_second=3.93426M/s
bench_gift_cofb::decrypt/32/128        38118 ns        38117 ns        18364 bytes_per_second=4.00312M/s
bench_gift_cofb::encrypt/32/256        66983 ns        66982 ns        10450 bytes_per_second=4.10046M/s
bench_gift_cofb::decrypt/32/256        65786 ns        65785 ns        10640 bytes_per_second=4.1751M/s
bench_gift_cofb::encrypt/32/512       123377 ns       123377 ns         5672 bytes_per_second=4.205M/s
bench_gift_cofb::decrypt/32/512       121119 ns       121117 ns         5779 bytes_per_second=4.28345M/s
bench_gift_cofb::encrypt/32/1024      236173 ns       236172 ns         2964 bytes_per_second=4.26418M/s
bench_gift_cofb::decrypt/32/1024      231794 ns       231790 ns         3020 bytes_per_second=4.34479M/s
bench_gift_cofb::encrypt/32/2048      461756 ns       461753 ns         1516 bytes_per_second=4.2959M/s
bench_gift_cofb::decrypt/32/2048      453119 ns       453111 ns         1545 bytes_per_second=4.37782M/s
bench_gift_cofb::encrypt/32/4096      912965 ns       912950 ns          767 bytes_per_second=4.31214M/s
bench_gift_cofb::decrypt/32/4096      895944 ns       895916 ns          781 bytes_per_second=4.39412M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-07-18T08:54:53+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        64.7 ns         64.7 ns     10811018 bytes_per_second=235.997M/s
bench_gift_cofb::gift_permute<2>         124 ns          124 ns      5625222 bytes_per_second=122.613M/s
bench_gift_cofb::gift_permute<3>         185 ns          185 ns      3781569 bytes_per_second=82.4952M/s
bench_gift_cofb::gift_permute<4>         248 ns          248 ns      2816513 bytes_per_second=61.4103M/s
bench_gift_cofb::gift_permute<40>       2506 ns         2506 ns       279435 bytes_per_second=6.08851M/s
bench_gift_cofb::encrypt/32/64         17666 ns        17665 ns        39646 bytes_per_second=5.18283M/s
bench_gift_cofb::decrypt/32/64         17674 ns        17673 ns        39605 bytes_per_second=5.18039M/s
bench_gift_cofb::encrypt/32/128        27832 ns        27830 ns        25161 bytes_per_second=5.48293M/s
bench_gift_cofb::decrypt/32/128        27925 ns        27922 ns        25202 bytes_per_second=5.46477M/s
bench_gift_cofb::encrypt/32/256        48108 ns        48098 ns        14555 bytes_per_second=5.7104M/s
bench_gift_cofb::decrypt/32/256        47852 ns        47847 ns        14618 bytes_per_second=5.7404M/s
bench_gift_cofb::encrypt/32/512        88289 ns        88281 ns         7933 bytes_per_second=5.87669M/s
bench_gift_cofb::decrypt/32/512        88004 ns        88000 ns         7960 bytes_per_second=5.89545M/s
bench_gift_cofb::encrypt/32/1024      168844 ns       168828 ns         4146 bytes_per_second=5.96513M/s
bench_gift_cofb::decrypt/32/1024      168077 ns       168075 ns         4164 bytes_per_second=5.99184M/s
bench_gift_cofb::encrypt/32/2048      329862 ns       329859 ns         2122 bytes_per_second=6.01361M/s
bench_gift_cofb::decrypt/32/2048      328588 ns       328585 ns         2130 bytes_per_second=6.03692M/s
bench_gift_cofb::encrypt/32/4096      652360 ns       652339 ns         1074 bytes_per_second=6.03485M/s
bench_gift_cofb::decrypt/32/4096      649506 ns       649485 ns         1078 bytes_per_second=6.06137M/s
```

## Example

GIFT-COFB is written as zero-dependency, header-only C++ library, which makes it easy to use --- just include header file `aead.hpp` and start using encrypt/ decrypt functions, placed inside `gift_cofb` namespace. Finally during compilation, let your compiler know where it can find GIFT-COFB header files.

I'm keeping an example [here](./example/gift_cofb.cpp), I suggest you go through that to understand usage of GIFT-COFB AEAD interface.

When compiled & executed, following instruction provided in aforelinked example file, you may see something like following in your console.

```bash
GIFT-COFB AEAD

Key       : 899ce2b50912e0c12ac5d8de52e28b58
Nonce     : 1372af739aa2767b75fee2d1ad7af248
Text      : dc2f1091be5def568ce3454c6acec6a18471bbb922f33e891f0a10165dd22e4c
Encrypted : fc1d7844f75de1f4d9f289b487cd389b43bfd8fb43ec2f105e335d56c8c62286
Tag       : b848923b790cdb43fffcb4de51c4ffe0
Decrypted : dc2f1091be5def568ce3454c6acec6a18471bbb922f33e891f0a10165dd22e4c
```
