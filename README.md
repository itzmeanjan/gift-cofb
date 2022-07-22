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
2022-07-22T09:43:33+00:00
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
bench_gift_cofb::gift_permute<1>        28.2 ns         28.2 ns     24864572 bytes_per_second=541.766M/s
bench_gift_cofb::gift_permute<2>        56.5 ns         56.5 ns     12377543 bytes_per_second=270.279M/s
bench_gift_cofb::gift_permute<3>        85.5 ns         85.5 ns      8192511 bytes_per_second=178.503M/s
bench_gift_cofb::gift_permute<4>         115 ns          115 ns      6035334 bytes_per_second=132.176M/s
bench_gift_cofb::gift_permute<40>       1161 ns         1161 ns       602222 bytes_per_second=13.1469M/s
bench_gift_cofb::encrypt/32/64          8196 ns         8196 ns        85363 bytes_per_second=11.1706M/s
bench_gift_cofb::decrypt/32/64          8171 ns         8171 ns        85457 bytes_per_second=11.205M/s
bench_gift_cofb::encrypt/32/128        12849 ns        12849 ns        54526 bytes_per_second=11.8758M/s
bench_gift_cofb::decrypt/32/128        12886 ns        12885 ns        54335 bytes_per_second=11.8418M/s
bench_gift_cofb::encrypt/32/256        22167 ns        22167 ns        31636 bytes_per_second=12.3905M/s
bench_gift_cofb::decrypt/32/256        21935 ns        21935 ns        31490 bytes_per_second=12.5216M/s
bench_gift_cofb::encrypt/32/512        40713 ns        40712 ns        17202 bytes_per_second=12.7432M/s
bench_gift_cofb::decrypt/32/512        41201 ns        41199 ns        16985 bytes_per_second=12.5925M/s
bench_gift_cofb::encrypt/32/1024       77862 ns        77860 ns         8977 bytes_per_second=12.9345M/s
bench_gift_cofb::decrypt/32/1024       77899 ns        77897 ns         8963 bytes_per_second=12.9283M/s
bench_gift_cofb::encrypt/32/2048      152295 ns       152291 ns         4598 bytes_per_second=13.0253M/s
bench_gift_cofb::decrypt/32/2048      152596 ns       152592 ns         4587 bytes_per_second=12.9996M/s
bench_gift_cofb::encrypt/32/4096      300885 ns       300878 ns         2324 bytes_per_second=13.0842M/s
bench_gift_cofb::decrypt/32/4096      302767 ns       302761 ns         2335 bytes_per_second=13.0029M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-22T13:44:23+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.22, 1.73, 1.84
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        17.6 ns         17.5 ns     39055308 bytes_per_second=869.474M/s
bench_gift_cofb::gift_permute<2>        34.6 ns         34.5 ns     20167389 bytes_per_second=441.809M/s
bench_gift_cofb::gift_permute<3>        56.5 ns         55.8 ns     13027619 bytes_per_second=273.32M/s
bench_gift_cofb::gift_permute<4>        72.3 ns         72.2 ns      9526920 bytes_per_second=211.25M/s
bench_gift_cofb::gift_permute<40>        698 ns          697 ns       936517 bytes_per_second=21.8881M/s
bench_gift_cofb::encrypt/32/64          4259 ns         4257 ns       166069 bytes_per_second=21.5083M/s
bench_gift_cofb::decrypt/32/64          4380 ns         4363 ns       158515 bytes_per_second=20.9842M/s
bench_gift_cofb::encrypt/32/128         7037 ns         6970 ns       103327 bytes_per_second=21.8914M/s
bench_gift_cofb::decrypt/32/128         6782 ns         6758 ns        99578 bytes_per_second=22.5797M/s
bench_gift_cofb::encrypt/32/256        11772 ns        11692 ns        60845 bytes_per_second=23.4906M/s
bench_gift_cofb::decrypt/32/256        12168 ns        12019 ns        58183 bytes_per_second=22.8514M/s
bench_gift_cofb::encrypt/32/512        20865 ns        20842 ns        32678 bytes_per_second=24.8918M/s
bench_gift_cofb::decrypt/32/512        20997 ns        20982 ns        33329 bytes_per_second=24.7258M/s
bench_gift_cofb::encrypt/32/1024       39720 ns        39688 ns        17505 bytes_per_second=25.3752M/s
bench_gift_cofb::decrypt/32/1024       42835 ns        42372 ns        16338 bytes_per_second=23.7673M/s
bench_gift_cofb::encrypt/32/2048       78770 ns        78607 ns         8852 bytes_per_second=25.2351M/s
bench_gift_cofb::decrypt/32/2048       83543 ns        82213 ns         8210 bytes_per_second=24.128M/s
bench_gift_cofb::encrypt/32/4096      159955 ns       158428 ns         4294 bytes_per_second=24.8489M/s
bench_gift_cofb::decrypt/32/4096      168506 ns       165391 ns         4247 bytes_per_second=23.8028M/s
```

### On AWS Graviton2

```bash
2022-07-22T09:42:23+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.03, 0.01
--------------------------------------------------------------------------------------------
Benchmark                                  Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute<1>        52.8 ns         52.8 ns     13252754 bytes_per_second=289.042M/s
bench_gift_cofb::gift_permute<2>         103 ns          103 ns      6773889 bytes_per_second=147.665M/s
bench_gift_cofb::gift_permute<3>         154 ns          154 ns      4553374 bytes_per_second=99.2574M/s
bench_gift_cofb::gift_permute<4>         208 ns          208 ns      3366292 bytes_per_second=73.3815M/s
bench_gift_cofb::gift_permute<40>       2063 ns         2063 ns       339276 bytes_per_second=7.39576M/s
bench_gift_cofb::encrypt/32/64         14619 ns        14619 ns        47884 bytes_per_second=6.26247M/s
bench_gift_cofb::decrypt/32/64         14628 ns        14628 ns        47854 bytes_per_second=6.25883M/s
bench_gift_cofb::encrypt/32/128        22944 ns        22943 ns        30509 bytes_per_second=6.65064M/s
bench_gift_cofb::decrypt/32/128        22943 ns        22943 ns        30509 bytes_per_second=6.6508M/s
bench_gift_cofb::encrypt/32/256        39593 ns        39592 ns        17680 bytes_per_second=6.93716M/s
bench_gift_cofb::decrypt/32/256        39576 ns        39575 ns        17688 bytes_per_second=6.94016M/s
bench_gift_cofb::encrypt/32/512        72893 ns        72893 ns         9603 bytes_per_second=7.11726M/s
bench_gift_cofb::decrypt/32/512        72841 ns        72839 ns         9610 bytes_per_second=7.12251M/s
bench_gift_cofb::encrypt/32/1024      139490 ns       139489 ns         5018 bytes_per_second=7.21979M/s
bench_gift_cofb::decrypt/32/1024      139370 ns       139367 ns         5023 bytes_per_second=7.22608M/s
bench_gift_cofb::encrypt/32/2048      272695 ns       272683 ns         2567 bytes_per_second=7.27453M/s
bench_gift_cofb::decrypt/32/2048      272413 ns       272411 ns         2569 bytes_per_second=7.2818M/s
bench_gift_cofb::encrypt/32/4096      539093 ns       539080 ns         1298 bytes_per_second=7.30275M/s
bench_gift_cofb::decrypt/32/4096      538682 ns       538674 ns         1299 bytes_per_second=7.30825M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-07-22T09:45:42+00:00
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
bench_gift_cofb::gift_permute<1>        28.2 ns         28.2 ns     24800952 bytes_per_second=540.646M/s
bench_gift_cofb::gift_permute<2>        50.9 ns         50.9 ns     13758773 bytes_per_second=299.773M/s
bench_gift_cofb::gift_permute<3>        75.8 ns         75.8 ns      9209411 bytes_per_second=201.218M/s
bench_gift_cofb::gift_permute<4>         101 ns          100 ns      6965291 bytes_per_second=151.834M/s
bench_gift_cofb::gift_permute<40>       1002 ns         1002 ns       698863 bytes_per_second=15.2283M/s
bench_gift_cofb::encrypt/32/64          6931 ns         6930 ns       100898 bytes_per_second=13.2113M/s
bench_gift_cofb::decrypt/32/64          6914 ns         6914 ns       100992 bytes_per_second=13.2417M/s
bench_gift_cofb::encrypt/32/128        10810 ns        10810 ns        64670 bytes_per_second=14.1157M/s
bench_gift_cofb::decrypt/32/128        10823 ns        10823 ns        64677 bytes_per_second=14.0981M/s
bench_gift_cofb::encrypt/32/256        18639 ns        18637 ns        37561 bytes_per_second=14.7369M/s
bench_gift_cofb::decrypt/32/256        18653 ns        18652 ns        37542 bytes_per_second=14.7252M/s
bench_gift_cofb::encrypt/32/512        34244 ns        34243 ns        20447 bytes_per_second=15.1507M/s
bench_gift_cofb::decrypt/32/512        34271 ns        34269 ns        20436 bytes_per_second=15.1391M/s
bench_gift_cofb::encrypt/32/1024       65391 ns        65387 ns        10703 bytes_per_second=15.4018M/s
bench_gift_cofb::decrypt/32/1024       65370 ns        65371 ns        10708 bytes_per_second=15.4056M/s
bench_gift_cofb::encrypt/32/2048      127720 ns       127721 ns         5483 bytes_per_second=15.531M/s
bench_gift_cofb::decrypt/32/2048      127618 ns       127611 ns         5487 bytes_per_second=15.5444M/s
bench_gift_cofb::encrypt/32/4096      252214 ns       252216 ns         2775 bytes_per_second=15.6087M/s
bench_gift_cofb::decrypt/32/4096      252045 ns       252035 ns         2778 bytes_per_second=15.6199M/s
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
