#pragma once
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

// GIFT-128 Block Cipher
namespace gift {

// GIFT-128 is a 40 -round iterative block cipher, see bottom of page 4 of
// GIFT-COFB specification
constexpr size_t ROUNDS = 40;

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

// GIFT-128 round constants which are generated from 6 -bit affine linear
// feedback shift register ( LFSR ), see table in page 7 of GIFT-COFB
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
constexpr uint8_t RC[ROUNDS] = {
  0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
  0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
  0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
  0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

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
sub_cells(state_t* const st)
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
perm_word(const uint32_t w, const uint32_t* const bit_perm)
{
  uint32_t tmp = 0u;

  for (size_t i = 0; i < 32; i++) {
    tmp |= ((w >> bit_perm[i]) & 0b1u) << i;
  }

  return tmp;
}

// Four different 32 -bit bit permutations are independently applied on each
// word of cipher state of GIFT-128 block cipher
//
// See PermBits specification defined in page 6 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
perm_bits(state_t* const st)
{
  st->cipher[0] = perm_word(st->cipher[0], BIT_PERM_S0);
  st->cipher[1] = perm_word(st->cipher[1], BIT_PERM_S1);
  st->cipher[2] = perm_word(st->cipher[2], BIT_PERM_S2);
  st->cipher[3] = perm_word(st->cipher[3], BIT_PERM_S3);
}

// Adds round keys and round constants to cipher state of GIFT-128 block cipher
//
// Note, round keys are extracted from key state of block cipher
//
// See page 6 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
add_round_keys(state_t* const st, const size_t r_idx)
{
  const uint32_t u = (static_cast<uint32_t>(st->key[2]) << 16) |
                     (static_cast<uint32_t>(st->key[3]) << 0);

  const uint32_t v = (static_cast<uint32_t>(st->key[6]) << 16) |
                     (static_cast<uint32_t>(st->key[7]) << 0);

  st->cipher[2] ^= u;
  st->cipher[1] ^= v;

  st->cipher[3] ^= (1u << 31) | static_cast<uint32_t>(RC[r_idx]);
}

// GIFT-128 key state updation function, as defined in top of page 7 of
// GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
update_key_state(state_t* const st)
{
  const uint16_t t0 = std::rotr(st->key[6], 2);
  const uint16_t t1 = std::rotr(st->key[7], 12);

  uint16_t tmp[6];
  std::memcpy(tmp, st->key, sizeof(tmp));
  std::memcpy(st->key + 2, tmp, sizeof(tmp));

  st->key[0] = t0;
  st->key[1] = t1;
}

// GIFT-128 round function, consisting of three sequential steps
//
// i) substitute cells
// ii) permute bits
// iii) add round keys and round constants
//
// See section 2.4.1 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
round(state_t* const st, const size_t r_idx)
{
  sub_cells(st);
  perm_bits(st);
  add_round_keys(st, r_idx);

  update_key_state(st);
}

// GIFT-128 substitution permutation network ( SPN ) block cipher, operating on
// initialized cipher/ key state, by applying 40 iterative rounds of GIFT-128
//
// See section 2.4.1 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
permute(state_t* const st)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    round(st, i);
  }
}

}
