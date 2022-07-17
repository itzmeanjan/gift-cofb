#pragma once
#include <bit>
#include <cstdint>
#include <cstring>

// GIFT-COFB common functions, used in both encrypt & decrypt
namespace gift_cofb_common {

// GIFT-COFB feedback function, which takes 128 -bit input and produces 128 -bit
// output, as defined in section 2.5 of specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
feedback(uint32_t* const y)
{
  const uint64_t y1_0 = static_cast<uint64_t>(y[0]);
  const uint64_t y1_1 = static_cast<uint64_t>(y[1]);

  const uint64_t y1 = (y1_0 << 32) | y1_1;
  const uint64_t y1_prime = std::rotl(y1, 1);

  std::memcpy(y + 0, y + 2, 8);

  y[2] = static_cast<uint32_t>(y1_prime >> 32);
  y[3] = static_cast<uint32_t>(y1_prime >> 0);
}

// Multiplying a 64 -bit element of field 2^64 ( with irreducible polynomial
// f(x) = x^64 + x^4 + x^3 + x + 1 ) by primitive element 0b10 ( = α = 2 s),
// as defined in section 2.1.2 of specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
lx2(uint32_t* const l)
{
  const uint64_t l0 = static_cast<uint64_t>(l[0]);
  const uint64_t l1 = static_cast<uint64_t>(l[1]);

  const uint64_t l2 = (l0 << 32) | l1;

  const uint8_t b63 = static_cast<uint8_t>(l2 >> 63);
  constexpr uint64_t br[2] = { 0ul, 0b11011ul };

  const uint64_t l3 = l2 << 1;
  const uint64_t l4 = l3 ^ br[b63];

  l[0] = static_cast<uint32_t>(l4 >> 32);
  l[1] = static_cast<uint32_t>(l4 >> 0);
}

// Multiplying a 64 -bit element of field 2^64 ( with irreducible polynomial
// f(x) = x^64 + x^4 + x^3 + x + 1 ) by field element 0b11 ( = α + 1 = 3 ),
// as defined in section 2.1.2 of specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
lx3(uint32_t* const l)
{
  // This is what is done below.
  //
  // a = b * 3
  //   = b * ( 2 + 1)
  //   = b * 2 + b * 1
  //   = lx2(b) ^ b
  //
  // | a, b ∈ F(2^64) with irreducible polynomial x^64 + x^4 + x^3 + x + 1
  //   lx2(b) = b * 2 ( see function above )

  uint32_t tmp[2];
  std::memcpy(tmp, l, 8);

  lx2(tmp);

  l[0] ^= tmp[0];
  l[1] ^= tmp[1];
}

}
