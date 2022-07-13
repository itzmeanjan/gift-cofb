#include "bench_gift.hpp"

// register gift-128 for benchmarking
BENCHMARK(bench_gift_cofb::gift_permute);

// benchmark runner main function
BENCHMARK_MAIN();
