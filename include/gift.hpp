#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>

// GIFT-128 Block Cipher
namespace gift {

// 32 -bit bit permutation, applied to S0 word of cipher state, as listed in
// table 2.2 of GIFT-COFB specification
constexpr uint32_t BIT_PERM_S0[32] = { 0, 4, 8,  12, 16, 20, 24, 28,
                                       3, 7, 11, 15, 19, 23, 27, 31,
                                       2, 6, 10, 14, 18, 22, 26, 30,
                                       1, 5, 9,  13, 17, 21, 25, 29 };

// 32 -bit bit permutation, applied to S1 word of cipher state, as listed in
// table 2.2 of GIFT-COFB specification
constexpr uint32_t BIT_PERM_S1[32] = { 1, 5, 9,  13, 17, 21, 25, 29,
                                       0, 4, 8,  12, 16, 20, 24, 28,
                                       3, 7, 11, 15, 19, 23, 27, 31,
                                       2, 6, 10, 14, 18, 22, 26, 30 };

// 32 -bit bit permutation, applied to S2 word of cipher state, as listed in
// table 2.2 of GIFT-COFB specification
constexpr uint32_t BIT_PERM_S2[32] = { 2, 6, 10, 14, 18, 22, 26, 30,
                                       1, 5, 9,  13, 17, 21, 25, 29,
                                       0, 4, 8,  12, 16, 20, 24, 28,
                                       3, 7, 11, 15, 19, 23, 27, 31 };

// 32 -bit bit permutation, applied to S3 word of cipher state, as listed in
// table 2.2 of GIFT-COFB specification
constexpr uint32_t BIT_PERM_S3[32] = { 3, 7, 11, 15, 19, 23, 27, 31,
                                       2, 6, 10, 14, 18, 22, 26, 30,
                                       1, 5, 9,  13, 17, 21, 25, 29,
                                       0, 4, 8,  12, 16, 20, 24, 28 };

// GIFT-128 block cipher state, as defined in section 2.4.1 of GIFT-COFB
// specification ( see page 5 )
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
struct state_t
{
  uint32_t cipher[4];
  uint16_t key[8];
};

// Initializing GIFT-128 block cipher state with plain text block and secret
// key, as defined in section 2.4.2 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
initialize(state_t* const __restrict st,        // GIFT-128 block cipher state
           const uint8_t* const __restrict txt, // 128 -bit plain text block
           const uint8_t* const __restrict key  // 128 -bit secret key
)
{
  for (size_t i = 0; i < 4; i++) {
    const size_t boff = i << 2;

    st->cipher[i] = (static_cast<uint32_t>(txt[boff ^ 0]) << 24) |
                    (static_cast<uint32_t>(txt[boff ^ 1]) << 16) |
                    (static_cast<uint32_t>(txt[boff ^ 2]) << 8) |
                    (static_cast<uint32_t>(txt[boff ^ 3]) << 0);
  }

  for (size_t i = 0; i < 8; i++) {
    const size_t boff = i << 1;

    st->key[i] = (static_cast<uint16_t>(key[boff ^ 0]) << 8) |
                 (static_cast<uint16_t>(key[boff ^ 1]) << 0);
  }
}

// Substitutes cells of cipher state with following instructions, as defined in
// page 5 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
subcells(state_t* const st)
{
  const uint32_t t0 = st->cipher[0] & st->cipher[2];
  st->cipher[1] ^= t0;

  const uint32_t t1 = st->cipher[1] & st->cipher[3];
  st->cipher[0] ^= t1;

  const uint32_t t2 = st->cipher[0] | st->cipher[1];
  st->cipher[2] ^= t2;

  st->cipher[3] ^= st->cipher[2];
  st->cipher[1] ^= st->cipher[3];
  st->cipher[3] = ~st->cipher[3];

  const uint32_t t3 = st->cipher[0] & st->cipher[1];
  st->cipher[2] ^= t3;

  std::swap(st->cipher[0], st->cipher[3]);
}

// Permutes 32 -bits of a word of cipher state of GIFT-128 block cipher (
// invoked as part of PermBits step )
inline static uint32_t
permword(const uint32_t w, const uint32_t* const bit_perm)
{
  uint32_t tmp = 0u;

  for (size_t i = 0; i < 32; i++) {
    tmp |= ((w >> i) & 0b1u) << bit_perm[i];
  }

  return tmp;
}

// Four different 32 -bit bit permutations are independently applied on each
// word of cipher state of GIFT-128 block cipher
//
// See PermBits specification defined in page 6 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
permbits(state_t* const st)
{
  st->cipher[0] = permword(st->cipher[0], BIT_PERM_S0);
  st->cipher[1] = permword(st->cipher[1], BIT_PERM_S1);
  st->cipher[2] = permword(st->cipher[2], BIT_PERM_S2);
  st->cipher[3] = permword(st->cipher[3], BIT_PERM_S3);
}

}
