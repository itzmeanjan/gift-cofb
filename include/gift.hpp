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

// Only bit 7 of 32 -bit word set
constexpr uint32_t B7 = 0b10000000u;

// Only bit 6 of 32 -bit word set
constexpr uint32_t B6 = 0b01000000u;

// Only bit 5 of 32 -bit word set
constexpr uint32_t B5 = 0b00100000u;

// Only bit 4 of 32 -bit word set
constexpr uint32_t B4 = 0b00010000u;

// Only bit 3 of 32 -bit word set
constexpr uint32_t B3 = 0b00001000u;

// Only bit 2 of 32 -bit word set
constexpr uint32_t B2 = 0b00000100u;

// Only bit 1 of 32 -bit word set
constexpr uint32_t B1 = 0b00000010u;

// Only bit 0 of 32 -bit word set
constexpr uint32_t B0 = 0b00000001u;

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

// Initializing GIFT-128 block cipher state with plain text block and secret
// key, as defined in section 2.4.2 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
initialize(state_t* const __restrict st,         // GIFT-128 block cipher state
           const uint32_t* const __restrict txt, // 128 -bit plain text block
           const uint8_t* const __restrict key   // 128 -bit secret key
)
{
  std::memcpy(st->cipher, txt, 16);

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

// Four different 32 -bit bit permutations are independently applied on each
// word of cipher state of GIFT-128 block cipher
//
// See PermBits specification defined in page 6 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
inline static void
perm_bits(state_t* const st)
{
  const uint32_t s0 = st->cipher[0];
  const uint32_t s1 = st->cipher[1];
  const uint32_t s2 = st->cipher[2];
  const uint32_t s3 = st->cipher[3];

  const uint32_t s0b0 = ((s0 >> 21) & B7) ^ ((s0 >> 18) & B6) ^
                        ((s0 >> 15) & B5) ^ ((s0 >> 12) & B4) ^
                        ((s0 >> 9) & B3) ^ ((s0 >> 6) & B2) ^ ((s0 >> 3) & B1) ^
                        ((s0 >> 0) & B0);

  const uint32_t s1b1 = ((s1 >> 21) & B7) ^ ((s1 >> 18) & B6) ^
                        ((s1 >> 15) & B5) ^ ((s1 >> 12) & B4) ^
                        ((s1 >> 9) & B3) ^ ((s1 >> 6) & B2) ^ ((s1 >> 3) & B1) ^
                        ((s1 >> 0) & B0);

  const uint32_t s1b0 = ((s1 >> 22) & B7) ^ ((s1 >> 19) & B6) ^
                        ((s1 >> 16) & B5) ^ ((s1 >> 13) & B4) ^
                        ((s1 >> 10) & B3) ^ ((s1 >> 7) & B2) ^
                        ((s1 >> 4) & B1) ^ ((s1 >> 1) & B0);

  const uint32_t s2b1 = ((s2 >> 22) & B7) ^ ((s2 >> 19) & B6) ^
                        ((s2 >> 16) & B5) ^ ((s2 >> 13) & B4) ^
                        ((s2 >> 10) & B3) ^ ((s2 >> 7) & B2) ^
                        ((s2 >> 4) & B1) ^ ((s2 >> 1) & B0);

  const uint32_t s2b0 = ((s2 >> 23) & B7) ^ ((s2 >> 20) & B6) ^
                        ((s2 >> 17) & B5) ^ ((s2 >> 14) & B4) ^
                        ((s2 >> 11) & B3) ^ ((s2 >> 8) & B2) ^
                        ((s2 >> 5) & B1) ^ ((s2 >> 2) & B0);

  const uint32_t s3b1 = ((s3 >> 23) & B7) ^ ((s3 >> 20) & B6) ^
                        ((s3 >> 17) & B5) ^ ((s3 >> 14) & B4) ^
                        ((s3 >> 11) & B3) ^ ((s3 >> 8) & B2) ^
                        ((s3 >> 5) & B1) ^ ((s3 >> 2) & B0);

  const uint32_t s3b0 = ((s3 >> 24) & B7) ^ ((s3 >> 21) & B6) ^
                        ((s3 >> 18) & B5) ^ ((s3 >> 15) & B4) ^
                        ((s3 >> 12) & B3) ^ ((s3 >> 9) & B2) ^
                        ((s3 >> 6) & B1) ^ ((s3 >> 3) & B0);

  const uint32_t s0b1 = ((s0 >> 24) & B7) ^ ((s0 >> 21) & B6) ^
                        ((s0 >> 18) & B5) ^ ((s0 >> 15) & B4) ^
                        ((s0 >> 12) & B3) ^ ((s0 >> 9) & B2) ^
                        ((s0 >> 6) & B1) ^ ((s0 >> 3) & B0);

  const uint32_t s0b2 = ((s0 >> 23) & B7) ^ ((s0 >> 20) & B6) ^
                        ((s0 >> 17) & B5) ^ ((s0 >> 14) & B4) ^
                        ((s0 >> 11) & B3) ^ ((s0 >> 8) & B2) ^
                        ((s0 >> 5) & B1) ^ ((s0 >> 2) & B0);

  const uint32_t s1b3 = ((s1 >> 23) & B7) ^ ((s1 >> 20) & B6) ^
                        ((s1 >> 17) & B5) ^ ((s1 >> 14) & B4) ^
                        ((s1 >> 11) & B3) ^ ((s1 >> 8) & B2) ^
                        ((s1 >> 5) & B1) ^ ((s1 >> 2) & B0);

  const uint32_t s1b2 = ((s1 >> 24) & B7) ^ ((s1 >> 21) & B6) ^
                        ((s1 >> 18) & B5) ^ ((s1 >> 15) & B4) ^
                        ((s1 >> 12) & B3) ^ ((s1 >> 9) & B2) ^
                        ((s1 >> 6) & B1) ^ ((s1 >> 3) & B0);

  const uint32_t s2b3 = ((s2 >> 24) & B7) ^ ((s2 >> 21) & B6) ^
                        ((s2 >> 18) & B5) ^ ((s2 >> 15) & B4) ^
                        ((s2 >> 12) & B3) ^ ((s2 >> 9) & B2) ^
                        ((s2 >> 6) & B1) ^ ((s2 >> 3) & B0);

  const uint32_t s2b2 = ((s2 >> 21) & B7) ^ ((s2 >> 18) & B6) ^
                        ((s2 >> 15) & B5) ^ ((s2 >> 12) & B4) ^
                        ((s2 >> 9) & B3) ^ ((s2 >> 6) & B2) ^ ((s2 >> 3) & B1) ^
                        ((s2 >> 0) & B0);

  const uint32_t s3b3 = ((s3 >> 21) & B7) ^ ((s3 >> 18) & B6) ^
                        ((s3 >> 15) & B5) ^ ((s3 >> 12) & B4) ^
                        ((s3 >> 9) & B3) ^ ((s3 >> 6) & B2) ^ ((s3 >> 3) & B1) ^
                        ((s3 >> 0) & B0);

  const uint32_t s3b2 = ((s3 >> 22) & B7) ^ ((s3 >> 19) & B6) ^
                        ((s3 >> 16) & B5) ^ ((s3 >> 13) & B4) ^
                        ((s3 >> 10) & B3) ^ ((s3 >> 7) & B2) ^
                        ((s3 >> 4) & B1) ^ ((s3 >> 1) & B0);

  const uint32_t s0b3 = ((s0 >> 22) & B7) ^ ((s0 >> 19) & B6) ^
                        ((s0 >> 16) & B5) ^ ((s0 >> 13) & B4) ^
                        ((s0 >> 10) & B3) ^ ((s0 >> 7) & B2) ^
                        ((s0 >> 4) & B1) ^ ((s0 >> 1) & B0);

  st->cipher[0] = (s0b3 << 24) ^ (s0b2 << 16) ^ (s0b1 << 8) ^ s0b0;
  st->cipher[1] = (s1b3 << 24) ^ (s1b2 << 16) ^ (s1b1 << 8) ^ s1b0;
  st->cipher[2] = (s2b3 << 24) ^ (s2b2 << 16) ^ (s2b1 << 8) ^ s2b0;
  st->cipher[3] = (s3b3 << 24) ^ (s3b2 << 16) ^ (s3b1 << 8) ^ s3b0;
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
// initialized cipher/ key state, by applying R iterative rounds of GIFT-128
//
// See section 2.4.1 of GIFT-COFB specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
template<const size_t R>
inline static void
permute(state_t* const st)
{
  for (size_t i = 0; i < R; i++) {
    round(st, i);
  }
}

}
