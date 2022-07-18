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
2022-07-18T07:50:32+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.06, 0.01, 0.00
-------------------------------------------------------------------------------------------
Benchmark                                 Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute          1529 ns         1529 ns       456430 bytes_per_second=9.9787M/s
bench_gift_cofb::encrypt/32/64        10927 ns        10927 ns        64041 bytes_per_second=8.37895M/s
bench_gift_cofb::decrypt/32/64        10811 ns        10811 ns        64729 bytes_per_second=8.46887M/s
bench_gift_cofb::encrypt/32/128       17148 ns        17147 ns        40828 bytes_per_second=8.89863M/s
bench_gift_cofb::decrypt/32/128       16979 ns        16979 ns        41235 bytes_per_second=8.98706M/s
bench_gift_cofb::encrypt/32/256       29585 ns        29585 ns        23662 bytes_per_second=9.28383M/s
bench_gift_cofb::decrypt/32/256       29232 ns        29231 ns        23952 bytes_per_second=9.3961M/s
bench_gift_cofb::encrypt/32/512       54459 ns        54458 ns        12854 bytes_per_second=9.52665M/s
bench_gift_cofb::decrypt/32/512       53799 ns        53798 ns        13012 bytes_per_second=9.64347M/s
bench_gift_cofb::encrypt/32/1024     104209 ns       104207 ns         6716 bytes_per_second=9.66423M/s
bench_gift_cofb::decrypt/32/1024     102874 ns       102872 ns         6802 bytes_per_second=9.78964M/s
bench_gift_cofb::encrypt/32/2048     203697 ns       203693 ns         3436 bytes_per_second=9.73839M/s
bench_gift_cofb::decrypt/32/2048     201193 ns       201188 ns         3480 bytes_per_second=9.85965M/s
bench_gift_cofb::encrypt/32/4096     402806 ns       402787 ns         1738 bytes_per_second=9.77383M/s
bench_gift_cofb::decrypt/32/4096     397774 ns       397767 ns         1760 bytes_per_second=9.89718M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-18T11:54:11+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.82, 1.60, 1.74
-------------------------------------------------------------------------------------------
Benchmark                                 Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute          1438 ns         1428 ns       481997 bytes_per_second=10.6819M/s
bench_gift_cofb::encrypt/32/64        10076 ns        10047 ns        69540 bytes_per_second=9.11284M/s
bench_gift_cofb::decrypt/32/64        10318 ns        10192 ns        68285 bytes_per_second=8.98307M/s
bench_gift_cofb::encrypt/32/128       15863 ns        15824 ns        44055 bytes_per_second=9.64272M/s
bench_gift_cofb::decrypt/32/128       15964 ns        15915 ns        43631 bytes_per_second=9.58763M/s
bench_gift_cofb::encrypt/32/256       27551 ns        27451 ns        25418 bytes_per_second=10.0054M/s
bench_gift_cofb::decrypt/32/256       27699 ns        27624 ns        25634 bytes_per_second=9.9427M/s
bench_gift_cofb::encrypt/32/512       51002 ns        50832 ns        13272 bytes_per_second=10.2061M/s
bench_gift_cofb::decrypt/32/512       50213 ns        50150 ns        13056 bytes_per_second=10.3449M/s
bench_gift_cofb::encrypt/32/1024      96430 ns        96141 ns         7208 bytes_per_second=10.475M/s
bench_gift_cofb::decrypt/32/1024      97035 ns        96743 ns         7189 bytes_per_second=10.4099M/s
bench_gift_cofb::encrypt/32/2048     188837 ns       188398 ns         3702 bytes_per_second=10.529M/s
bench_gift_cofb::decrypt/32/2048     189977 ns       189458 ns         3654 bytes_per_second=10.4701M/s
bench_gift_cofb::encrypt/32/4096     377483 ns       375174 ns         1886 bytes_per_second=10.4932M/s
bench_gift_cofb::decrypt/32/4096     375004 ns       373887 ns         1834 bytes_per_second=10.5293M/s
```

### On AWS Graviton2

```bash
2022-07-18T07:49:11+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.02, 0.01
-------------------------------------------------------------------------------------------
Benchmark                                 Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute          3441 ns         3441 ns       203489 bytes_per_second=4.4349M/s
bench_gift_cofb::encrypt/32/64        24692 ns        24691 ns        28355 bytes_per_second=3.70792M/s
bench_gift_cofb::decrypt/32/64        24288 ns        24287 ns        28827 bytes_per_second=3.76955M/s
bench_gift_cofb::encrypt/32/128       38793 ns        38793 ns        18049 bytes_per_second=3.9334M/s
bench_gift_cofb::decrypt/32/128       38138 ns        38127 ns        18365 bytes_per_second=4.0021M/s
bench_gift_cofb::encrypt/32/256       66996 ns        66995 ns        10449 bytes_per_second=4.09968M/s
bench_gift_cofb::decrypt/32/256       65783 ns        65781 ns        10641 bytes_per_second=4.17536M/s
bench_gift_cofb::encrypt/32/512      123404 ns       123403 ns         5674 bytes_per_second=4.20411M/s
bench_gift_cofb::decrypt/32/512      121143 ns       121139 ns         5780 bytes_per_second=4.28266M/s
bench_gift_cofb::encrypt/32/1024     236221 ns       236218 ns         2964 bytes_per_second=4.26334M/s
bench_gift_cofb::decrypt/32/1024     231839 ns       231831 ns         3020 bytes_per_second=4.34402M/s
bench_gift_cofb::encrypt/32/2048     461935 ns       461928 ns         1516 bytes_per_second=4.29427M/s
bench_gift_cofb::decrypt/32/2048     453176 ns       453162 ns         1544 bytes_per_second=4.37734M/s
bench_gift_cofb::encrypt/32/4096     913225 ns       913212 ns          767 bytes_per_second=4.3109M/s
bench_gift_cofb::decrypt/32/4096     896147 ns       896121 ns          781 bytes_per_second=4.39312M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```bash
2022-07-18T07:55:38+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.00, 0.00, 0.00
-------------------------------------------------------------------------------------------
Benchmark                                 Time             CPU   Iterations UserCounters...
-------------------------------------------------------------------------------------------
bench_gift_cofb::gift_permute          2518 ns         2518 ns       276604 bytes_per_second=6.05896M/s
bench_gift_cofb::encrypt/32/64        17654 ns        17654 ns        39657 bytes_per_second=5.18597M/s
bench_gift_cofb::decrypt/32/64        17644 ns        17645 ns        39660 bytes_per_second=5.18872M/s
bench_gift_cofb::encrypt/32/128       27749 ns        27749 ns        25214 bytes_per_second=5.49883M/s
bench_gift_cofb::decrypt/32/128       27768 ns        27768 ns        25221 bytes_per_second=5.4951M/s
bench_gift_cofb::encrypt/32/256       47911 ns        47910 ns        14610 bytes_per_second=5.73285M/s
bench_gift_cofb::decrypt/32/256       47973 ns        47973 ns        14599 bytes_per_second=5.72525M/s
bench_gift_cofb::encrypt/32/512       88269 ns        88267 ns         7932 bytes_per_second=5.87759M/s
bench_gift_cofb::decrypt/32/512       88295 ns        88295 ns         7933 bytes_per_second=5.87577M/s
bench_gift_cofb::encrypt/32/1024     168980 ns       168981 ns         4142 bytes_per_second=5.95971M/s
bench_gift_cofb::decrypt/32/1024     168962 ns       168961 ns         4145 bytes_per_second=5.96041M/s
bench_gift_cofb::encrypt/32/2048     330457 ns       330460 ns         2118 bytes_per_second=6.00268M/s
bench_gift_cofb::decrypt/32/2048     330277 ns       330275 ns         2120 bytes_per_second=6.00603M/s
bench_gift_cofb::encrypt/32/4096     653030 ns       653027 ns         1072 bytes_per_second=6.02849M/s
bench_gift_cofb::decrypt/32/4096     652990 ns       652971 ns         1072 bytes_per_second=6.02901M/s
```
