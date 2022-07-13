#pragma once
#include "gift.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark GIFT-COFB Authenticated Encryption on CPU
namespace bench_gift_cofb {

// Benchmark GIFT-128 permutation ( 40 -rounds ) on CPU, by generating 128 -bit
// random plain text and secret key
static void
gift_permute(benchmark::State& state)
{
  constexpr size_t N = 16;

  uint8_t* txt = static_cast<uint8_t*>(std::malloc(N));
  uint8_t* key = static_cast<uint8_t*>(std::malloc(N));

  random_data(txt, N);
  random_data(key, N);

  gift::state_t st;
  gift::initialize(&st, txt, key);

  for (auto _ : state) {
    gift::permute(&st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(N * state.iterations()));

  std::free(txt);
  std::free(key);
}

}
