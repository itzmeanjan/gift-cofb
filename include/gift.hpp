#pragma once
#include <cstddef>
#include <cstdint>

// GIFT-128 Block Cipher
namespace gift {

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
initialize(state_t* const st,                   // GIFT-128 block cipher state
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

}
