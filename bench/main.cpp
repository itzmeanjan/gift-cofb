#include "bench_gift.hpp"
#include "bench_gift_cofb.hpp"

// register gift-128 for benchmarking
BENCHMARK(bench_gift_cofb::gift_permute);

// register gift-cofb aead for benchmarking
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 64 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 64 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 128 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 128 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 256 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 256 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 512 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 512 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 1024 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 2048 });
BENCHMARK(bench_gift_cofb::encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_gift_cofb::decrypt)->Args({ 32, 4096 });

// benchmark runner main function
BENCHMARK_MAIN();
