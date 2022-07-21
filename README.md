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
2022-07-21T10:49:17+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.07, 0.02, 0.00
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        29.8 ns         29.8 ns     23530891 bytes_per_second=512.345M/s
bench_gift_cofb::gift_permute<2>        63.5 ns         63.5 ns     11029182 bytes_per_second=240.313M/s
bench_gift_cofb::gift_permute<3>        92.6 ns         92.6 ns      7566764 bytes_per_second=164.87M/s
bench_gift_cofb::gift_permute<4>         121 ns          121 ns      5790216 bytes_per_second=126.211M/s
bench_gift_cofb::gift_permute<40>       1168 ns         1168 ns       599762 bytes_per_second=13.0662M/s
bench_gift_cofb::encrypt/32/64          8163 ns         8162 ns        85775 bytes_per_second=11.2164M/s
bench_gift_cofb::decrypt/32/64          8147 ns         8147 ns        85948 bytes_per_second=11.2381M/s
bench_gift_cofb::encrypt/32/128        12841 ns        12841 ns        54514 bytes_per_second=11.8827M/s
bench_gift_cofb::decrypt/32/128        12801 ns        12800 ns        54707 bytes_per_second=11.9205M/s
bench_gift_cofb::encrypt/32/256        22180 ns        22179 ns        31561 bytes_per_second=12.3838M/s
bench_gift_cofb::decrypt/32/256        22113 ns        22113 ns        31653 bytes_per_second=12.4209M/s
bench_gift_cofb::encrypt/32/512        40857 ns        40856 ns        17127 bytes_per_second=12.6983M/s
bench_gift_cofb::decrypt/32/512        40756 ns        40755 ns        17176 bytes_per_second=12.7297M/s
bench_gift_cofb::encrypt/32/1024       78241 ns        78239 ns         8944 bytes_per_second=12.8718M/s
bench_gift_cofb::decrypt/32/1024       77996 ns        77994 ns         8974 bytes_per_second=12.9123M/s
bench_gift_cofb::encrypt/32/2048      152951 ns       152947 ns         4576 bytes_per_second=12.9695M/s
bench_gift_cofb::decrypt/32/2048      152426 ns       152422 ns         4592 bytes_per_second=13.0141M/s
bench_gift_cofb::encrypt/32/4096      302457 ns       302451 ns         2315 bytes_per_second=13.0162M/s
bench_gift_cofb::decrypt/32/4096      301401 ns       301395 ns         2322 bytes_per_second=13.0618M/s
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
2022-07-21T10:46:10+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.18, 0.05, 0.01
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        85.0 ns         84.9 ns      8236545 bytes_per_second=179.622M/s
bench_gift_cofb::gift_permute<2>         177 ns          177 ns      3962790 bytes_per_second=86.3807M/s
bench_gift_cofb::gift_permute<3>         261 ns          261 ns      2684927 bytes_per_second=58.4958M/s
bench_gift_cofb::gift_permute<4>         346 ns          346 ns      2024627 bytes_per_second=44.1328M/s
bench_gift_cofb::gift_permute<40>       3410 ns         3410 ns       205259 bytes_per_second=4.47441M/s
bench_gift_cofb::encrypt/32/64         24197 ns        24196 ns        28929 bytes_per_second=3.78372M/s
bench_gift_cofb::decrypt/32/64         24067 ns        24067 ns        29085 bytes_per_second=3.80406M/s
bench_gift_cofb::encrypt/32/128        37956 ns        37955 ns        18443 bytes_per_second=4.02019M/s
bench_gift_cofb::decrypt/32/128        37640 ns        37640 ns        18597 bytes_per_second=4.05389M/s
bench_gift_cofb::encrypt/32/256        65473 ns        65472 ns        10691 bytes_per_second=4.19502M/s
bench_gift_cofb::decrypt/32/256        64786 ns        64785 ns        10804 bytes_per_second=4.23953M/s
bench_gift_cofb::encrypt/32/512       120510 ns       120509 ns         5809 bytes_per_second=4.30506M/s
bench_gift_cofb::decrypt/32/512       119079 ns       119077 ns         5879 bytes_per_second=4.35685M/s
bench_gift_cofb::encrypt/32/1024      230584 ns       230583 ns         3036 bytes_per_second=4.36754M/s
bench_gift_cofb::decrypt/32/1024      227656 ns       227654 ns         3075 bytes_per_second=4.42373M/s
bench_gift_cofb::encrypt/32/2048      450730 ns       450720 ns         1553 bytes_per_second=4.40105M/s
bench_gift_cofb::decrypt/32/2048      444825 ns       444822 ns         1574 bytes_per_second=4.45941M/s
bench_gift_cofb::encrypt/32/4096      891281 ns       891275 ns          785 bytes_per_second=4.417M/s
bench_gift_cofb::decrypt/32/4096      879147 ns       879141 ns          796 bytes_per_second=4.47797M/s
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
