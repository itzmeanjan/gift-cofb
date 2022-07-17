#pragma once
#include "gift.hpp"

// GIFT-COFB Authenticated Encryption with Associated Data
namespace gift_cofb {

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

}
