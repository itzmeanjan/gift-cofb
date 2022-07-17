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

// Given 128 -bit secret key, 128 -bit public message nonce, N -bytes associated
// data ( which is never encrypted ) and M -bytes plain text ( which is
// encrypted ) | N, M >= 0, this routine computes M -bytes encrypted text and
// 128 -bit authentication tag, using GIFT-COFB AEAD
//
// See algorithmic specification in figure 2.3 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
static void
encrypt(const uint8_t* const __restrict key,   // 128 -bit key
        const uint8_t* const __restrict nonce, // 128 -bit nonce
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) | >= 0
        const uint8_t* const __restrict txt,   // M -bytes plain text
        uint8_t* const __restrict enc,         // M -bytes encrypted text
        const size_t ctlen,                    // len(enc) = len(txt) | >= 0
        uint8_t* const __restrict tag          // 128 -bit authentication tag
)
{
  gift::state_t st;
  gift::initialize(&st, nonce, key);
  gift::permute(&st);

  uint32_t tmp[4];

  uint32_t y[4];
  std::memcpy(y, st.cipher, sizeof(y));

  uint32_t l[2];
  std::memcpy(l, y, sizeof(l));

  {
    const size_t full_blk_cnt = dlen >> 4;
    const size_t rm_bytes = dlen & 15;

    constexpr size_t br0[2] = { 0, 1 };
    const bool flg0 = (dlen == 0) | (rm_bytes > 0);

    const size_t tot_blk_cnt = full_blk_cnt + br0[flg0];

    size_t off = 0;
    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      lx2(l);

      std::memcpy(tmp, y, sizeof(tmp));
      feedback(tmp);

      uint32_t blk[4];

      for (size_t j = 0; j < 4; j++) {
        const size_t boff = j << 2;
        blk[j] = (static_cast<uint32_t>(data[off + (boff ^ 0)]) << 24) |
                 (static_cast<uint32_t>(data[off + (boff ^ 1)]) << 16) |
                 (static_cast<uint32_t>(data[off + (boff ^ 2)]) << 8) |
                 (static_cast<uint32_t>(data[off + (boff ^ 3)]) << 0);
      }

      off += 16;

      blk[0] ^= tmp[0] ^ l[0];
      blk[1] ^= tmp[1] ^ l[1];
      blk[2] ^= tmp[2];
      blk[3] ^= tmp[3];

      gift::initialize(&st, blk, key);
      gift::permute(&st);

      std::memcpy(y, st.cipher, sizeof(y));
    }

    if (rm_bytes == 0 && dlen > 0) {
      lx3(l);
    } else {
      lx3(l);
      lx3(l);
    }

    if (ctlen == 0) {
      lx3(l);
      lx3(l);
    }

    uint32_t padded_blk[4];
    std::memset(padded_blk, 0, sizeof(padded_blk));

    const size_t to_read = dlen - off;

    const size_t word_cnt = to_read >> 2;
    const size_t left_bytes = to_read & 3;

    for (size_t i = 0; i < word_cnt; i++) {
      const size_t boff = i << 2;
      padded_blk[i] = (static_cast<uint32_t>(data[off + (boff ^ 0)]) << 24) |
                      (static_cast<uint32_t>(data[off + (boff ^ 1)]) << 16) |
                      (static_cast<uint32_t>(data[off + (boff ^ 2)]) << 8) |
                      (static_cast<uint32_t>(data[off + (boff ^ 3)]) << 0);
    }

    off += word_cnt << 2;

    uint32_t w = 0b10000000u << ((3ul - left_bytes) << 3);
    for (size_t i = 0; i < left_bytes; i++) {
      w |= static_cast<uint32_t>(data[off + i]) << ((3ul - i) << 3);
    }

    off += left_bytes;

    const uint32_t br1[2] = { 0, w };
    const uint32_t br2[2] = { 1, 0 };

    const bool flg1 = static_cast<bool>(word_cnt ^ 4);

    padded_blk[word_cnt - br2[flg1]] ^= br1[to_read < 16];

    std::memcpy(tmp, y, sizeof(tmp));
    feedback(tmp);

    padded_blk[0] ^= tmp[0] ^ l[0];
    padded_blk[1] ^= tmp[1] ^ l[1];
    padded_blk[2] ^= tmp[2];
    padded_blk[3] ^= tmp[3];

    gift::initialize(&st, padded_blk, key);
    gift::permute(&st);

    std::memcpy(y, st.cipher, sizeof(y));
  }

  if (ctlen > 0) {
    const size_t full_blk_cnt = ctlen >> 4;
    const size_t rm_bytes = ctlen & 15;

    constexpr size_t br0[2] = { 0, 1 };
    const bool flg0 = (ctlen == 0) | (rm_bytes > 0);

    const size_t tot_blk_cnt = full_blk_cnt + br0[flg0];

    size_t off = 0;
    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      lx2(l);

      uint32_t blk[4];

      for (size_t j = 0; j < 4; j++) {
        const size_t boff = j << 2;

        blk[j] = (static_cast<uint32_t>(txt[off + (boff ^ 0)]) << 24) |
                 (static_cast<uint32_t>(txt[off + (boff ^ 1)]) << 16) |
                 (static_cast<uint32_t>(txt[off + (boff ^ 2)]) << 8) |
                 (static_cast<uint32_t>(txt[off + (boff ^ 3)]) << 0);

        const uint32_t w = blk[j] ^ y[j];

        enc[off + (boff ^ 0)] = static_cast<uint8_t>(w >> 24);
        enc[off + (boff ^ 1)] = static_cast<uint8_t>(w >> 16);
        enc[off + (boff ^ 2)] = static_cast<uint8_t>(w >> 8);
        enc[off + (boff ^ 3)] = static_cast<uint8_t>(w >> 0);
      }

      off += 16;

      std::memcpy(tmp, y, sizeof(tmp));
      feedback(tmp);

      blk[0] ^= tmp[0] ^ l[0];
      blk[1] ^= tmp[1] ^ l[1];
      blk[2] ^= tmp[2];
      blk[3] ^= tmp[3];

      gift::initialize(&st, blk, key);
      gift::permute(&st);

      std::memcpy(y, st.cipher, sizeof(y));
    }

    if (rm_bytes == 0) {
      lx3(l);
    } else {
      lx3(l);
      lx3(l);
    }

    uint32_t padded_blk[4];
    std::memset(padded_blk, 0, sizeof(padded_blk));

    const size_t to_read = ctlen - off;

    const size_t word_cnt = to_read >> 2;
    const size_t left_bytes = to_read & 3;

    for (size_t i = 0; i < word_cnt; i++) {
      const size_t boff = i << 2;

      padded_blk[i] = (static_cast<uint32_t>(txt[off + (boff ^ 0)]) << 24) |
                      (static_cast<uint32_t>(txt[off + (boff ^ 1)]) << 16) |
                      (static_cast<uint32_t>(txt[off + (boff ^ 2)]) << 8) |
                      (static_cast<uint32_t>(txt[off + (boff ^ 3)]) << 0);
    }

    off += word_cnt << 2;

    uint32_t w = 0b10000000u << ((3ul - left_bytes) << 3);
    for (size_t i = 0; i < left_bytes; i++) {
      w |= static_cast<uint32_t>(txt[off + i]) << ((3ul - i) << 3);
    }

    off -= word_cnt << 2;

    const uint32_t br1[2] = { 0, w };
    const uint32_t br2[2] = { 1, 0 };

    const bool flg1 = static_cast<bool>(word_cnt ^ 4);

    padded_blk[word_cnt - br2[flg1]] ^= br1[to_read < 16];

    uint32_t ciphered_blk[4];
    for (size_t i = 0; i < 4; i++) {
      ciphered_blk[i] = padded_blk[i] ^ y[i];
    }

    for (size_t i = 0; i < to_read; i++) {
      const size_t woff = i >> 2;
      const size_t boff = i & 3;
      const size_t soff = (3 - boff) << 3;

      enc[off + i] = static_cast<uint8_t>(ciphered_blk[woff] >> soff);
    }

    std::memcpy(tmp, y, sizeof(tmp));
    feedback(tmp);

    padded_blk[0] ^= tmp[0] ^ l[0];
    padded_blk[1] ^= tmp[1] ^ l[1];
    padded_blk[2] ^= tmp[2];
    padded_blk[3] ^= tmp[3];

    gift::initialize(&st, padded_blk, key);
    gift::permute(&st);

    std::memcpy(y, st.cipher, sizeof(y));
  }

  for (size_t i = 0; i < 4; i++) {
    const size_t boff = i << 2;

    tag[boff ^ 0] = static_cast<uint8_t>(y[i] >> 24);
    tag[boff ^ 1] = static_cast<uint8_t>(y[i] >> 16);
    tag[boff ^ 2] = static_cast<uint8_t>(y[i] >> 8);
    tag[boff ^ 3] = static_cast<uint8_t>(y[i] >> 0);
  }
}

// Given 128 -bit secret key, 128 -bit public message nonce, 128 -bit
// authentication tag, N -bytes associated data ( which was never encrypted )
// and M -bytes encrypted text | N, M >= 0, this routine computes M -bytes
// decrypted text and boolean verification flag, using GIFT-COFB AEAD
//
// Before consuming decrypted bytes, ensure presence of truth value in
// verification flag.
//
// See algorithmic specification in figure 2.3 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
static bool
decrypt(const uint8_t* const __restrict key,   // 128 -bit key
        const uint8_t* const __restrict nonce, // 128 -bit nonce
        const uint8_t* const __restrict tag,   // 128 -bit authentication tag
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) | >= 0
        const uint8_t* const __restrict enc,   // M -bytes encrypted text
        uint8_t* const __restrict txt,         // M -bytes decrypted text
        const size_t ctlen                     // len(enc) = len(txt) | >= 0
)
{
  gift::state_t st;
  gift::initialize(&st, nonce, key);
  gift::permute(&st);

  uint32_t tmp[4];

  uint32_t y[4];
  std::memcpy(y, st.cipher, sizeof(y));

  uint32_t l[2];
  std::memcpy(l, y, sizeof(l));

  {
    const size_t full_blk_cnt = dlen >> 4;
    const size_t rm_bytes = dlen & 15;

    constexpr size_t br0[2] = { 0, 1 };
    const bool flg0 = (dlen == 0) | (rm_bytes > 0);

    const size_t tot_blk_cnt = full_blk_cnt + br0[flg0];

    size_t off = 0;
    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      lx2(l);

      std::memcpy(tmp, y, sizeof(tmp));
      feedback(tmp);

      uint32_t blk[4];

      for (size_t j = 0; j < 4; j++) {
        const size_t boff = j << 2;
        blk[j] = (static_cast<uint32_t>(data[off + (boff ^ 0)]) << 24) |
                 (static_cast<uint32_t>(data[off + (boff ^ 1)]) << 16) |
                 (static_cast<uint32_t>(data[off + (boff ^ 2)]) << 8) |
                 (static_cast<uint32_t>(data[off + (boff ^ 3)]) << 0);
      }

      off += 16;

      blk[0] ^= tmp[0] ^ l[0];
      blk[1] ^= tmp[1] ^ l[1];
      blk[2] ^= tmp[2];
      blk[3] ^= tmp[3];

      gift::initialize(&st, blk, key);
      gift::permute(&st);

      std::memcpy(y, st.cipher, sizeof(y));
    }

    if (rm_bytes == 0 && dlen > 0) {
      lx3(l);
    } else {
      lx3(l);
      lx3(l);
    }

    if (ctlen == 0) {
      lx3(l);
      lx3(l);
    }

    uint32_t padded_blk[4];
    std::memset(padded_blk, 0, sizeof(padded_blk));

    const size_t to_read = dlen - off;

    const size_t word_cnt = to_read >> 2;
    const size_t left_bytes = to_read & 3;

    for (size_t i = 0; i < word_cnt; i++) {
      const size_t boff = i << 2;
      padded_blk[i] = (static_cast<uint32_t>(data[off + (boff ^ 0)]) << 24) |
                      (static_cast<uint32_t>(data[off + (boff ^ 1)]) << 16) |
                      (static_cast<uint32_t>(data[off + (boff ^ 2)]) << 8) |
                      (static_cast<uint32_t>(data[off + (boff ^ 3)]) << 0);
    }

    off += word_cnt << 2;

    uint32_t w = 0b10000000u << ((3ul - left_bytes) << 3);
    for (size_t i = 0; i < left_bytes; i++) {
      w |= static_cast<uint32_t>(data[off + i]) << ((3ul - i) << 3);
    }

    off += left_bytes;

    const uint32_t br1[2] = { 0, w };
    const uint32_t br2[2] = { 1, 0 };

    const bool flg1 = static_cast<bool>(word_cnt ^ 4);

    padded_blk[word_cnt - br2[flg1]] ^= br1[to_read < 16];

    std::memcpy(tmp, y, sizeof(tmp));
    feedback(tmp);

    padded_blk[0] ^= tmp[0] ^ l[0];
    padded_blk[1] ^= tmp[1] ^ l[1];
    padded_blk[2] ^= tmp[2];
    padded_blk[3] ^= tmp[3];

    gift::initialize(&st, padded_blk, key);
    gift::permute(&st);

    std::memcpy(y, st.cipher, sizeof(y));
  }

  if (ctlen > 0) {
    const size_t full_blk_cnt = ctlen >> 4;
    const size_t rm_bytes = ctlen & 15;

    constexpr size_t br0[2] = { 0, 1 };
    const bool flg0 = (ctlen == 0) | (rm_bytes > 0);

    const size_t tot_blk_cnt = full_blk_cnt + br0[flg0];

    size_t off = 0;
    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      lx2(l);

      uint32_t eblk[4];
      uint32_t dblk[4];

      for (size_t j = 0; j < 4; j++) {
        const size_t boff = j << 2;

        eblk[j] = (static_cast<uint32_t>(enc[off + (boff ^ 0)]) << 24) |
                  (static_cast<uint32_t>(enc[off + (boff ^ 1)]) << 16) |
                  (static_cast<uint32_t>(enc[off + (boff ^ 2)]) << 8) |
                  (static_cast<uint32_t>(enc[off + (boff ^ 3)]) << 0);

        dblk[j] = eblk[j] ^ y[j];

        txt[off + (boff ^ 0)] = static_cast<uint8_t>(dblk[i] >> 24);
        txt[off + (boff ^ 1)] = static_cast<uint8_t>(dblk[i] >> 16);
        txt[off + (boff ^ 2)] = static_cast<uint8_t>(dblk[i] >> 8);
        txt[off + (boff ^ 3)] = static_cast<uint8_t>(dblk[i] >> 0);
      }

      off += 16;

      std::memcpy(tmp, y, sizeof(tmp));
      feedback(tmp);

      dblk[0] ^= tmp[0] ^ l[0];
      dblk[1] ^= tmp[1] ^ l[1];
      dblk[2] ^= tmp[2];
      dblk[3] ^= tmp[3];

      gift::initialize(&st, dblk, key);
      gift::permute(&st);

      std::memcpy(y, st.cipher, sizeof(y));
    }

    if (rm_bytes == 0) {
      lx3(l);
    } else {
      lx3(l);
      lx3(l);
    }

    uint32_t epadded_blk[4];
    uint32_t dpadded_blk[4];

    std::memset(epadded_blk, 0, sizeof(epadded_blk));
    std::memset(dpadded_blk, 0, sizeof(dpadded_blk));

    const size_t to_read = ctlen - off;

    const size_t word_cnt = to_read >> 2;
    const size_t left_bytes = to_read & 3;

    for (size_t i = 0; i < word_cnt; i++) {
      const size_t boff = i << 2;

      epadded_blk[i] = (static_cast<uint32_t>(enc[off + (boff ^ 0)]) << 24) |
                       (static_cast<uint32_t>(enc[off + (boff ^ 1)]) << 16) |
                       (static_cast<uint32_t>(enc[off + (boff ^ 2)]) << 8) |
                       (static_cast<uint32_t>(enc[off + (boff ^ 3)]) << 0);
    }

    off += word_cnt << 2;

    uint32_t w = 0b10000000u << ((3ul - left_bytes) << 3);
    for (size_t i = 0; i < left_bytes; i++) {
      w |= static_cast<uint32_t>(enc[off + i]) << ((3ul - i) << 3);
    }

    off -= word_cnt << 2;

    const uint32_t br1[2] = { 0, w };
    const uint32_t br2[2] = { 1, 0 };

    const bool flg1 = static_cast<bool>(word_cnt ^ 4);

    epadded_blk[word_cnt - br2[flg1]] ^= br1[to_read < 16];

    for (size_t i = 0; i < 4; i++) {
      dpadded_blk[i] = epadded_blk[i] ^ y[i];
    }

    for (size_t i = 0; i < to_read; i++) {
      const size_t woff = i >> 2;
      const size_t boff = i & 3;
      const size_t soff = (3 - boff) << 3;

      txt[off + i] = static_cast<uint8_t>(dpadded_blk[woff] >> soff);
    }

    // Line 25 of decryption algorithm in figure 2.3 of GIFT-COFB specification
    // https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
    //
    // Implements truncation ( skipped, because not required ) and padding logic

    std::memset(dpadded_blk + word_cnt, 0, (4 - word_cnt) << 2);
    off += word_cnt << 2;

    uint32_t w_ = 0b10000000u << ((3ul - left_bytes) << 3);
    for (size_t i = 0; i < left_bytes; i++) {
      w_ |= static_cast<uint32_t>(txt[off + i]) << ((3ul - i) << 3);
    }

    off -= word_cnt << 2;

    const uint32_t br3[2] = { 0, w_ };

    dpadded_blk[word_cnt - br2[flg1]] ^= br3[to_read < 16];

    // --- truncation/ padding ends ---

    std::memcpy(tmp, y, sizeof(tmp));
    feedback(tmp);

    dpadded_blk[0] ^= tmp[0] ^ l[0];
    dpadded_blk[1] ^= tmp[1] ^ l[1];
    dpadded_blk[2] ^= tmp[2];
    dpadded_blk[3] ^= tmp[3];

    gift::initialize(&st, dpadded_blk, key);
    gift::permute(&st);

    std::memcpy(y, st.cipher, sizeof(y));
  }

  uint8_t tag_[16];

  for (size_t i = 0; i < 4; i++) {
    const size_t boff = i << 2;

    tag_[boff ^ 0] = static_cast<uint8_t>(y[i] >> 24);
    tag_[boff ^ 1] = static_cast<uint8_t>(y[i] >> 16);
    tag_[boff ^ 2] = static_cast<uint8_t>(y[i] >> 8);
    tag_[boff ^ 3] = static_cast<uint8_t>(y[i] >> 0);
  }

  bool flg = false;

  for (size_t i = 0; i < 16; i++) {
    flg |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  return !flg;
}

}
