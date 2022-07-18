#include "aead.hpp"
#include "utils.hpp"
#include <cassert>
#include <iostream>

// Compile it with
//
// g++ -std=c++20 -Wall -O3 -I ./include example/gift_cofb.cpp
int
main()
{
  uint8_t key[16], nonce[16], tag[16];
  uint8_t data[32], txt[32], enc[32], dec[32];

  // generate random key, nonce, associated data & plain text
  random_data(key, sizeof(key));
  random_data(nonce, sizeof(nonce));
  random_data(data, sizeof(data));
  random_data(txt, sizeof(txt));

  using namespace gift_cofb;

  // attempt to encrypt plain text
  encrypt(key, nonce, data, sizeof(data), txt, enc, sizeof(txt), tag);
  // attempt to decrypt cipher text
  bool f = decrypt(key, nonce, tag, data, sizeof(data), enc, dec, sizeof(enc));

  // check integrity
  assert(f);

  // check plain text & decrypted text for equality
  for (size_t i = 0; i < sizeof(txt); i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  std::cout << "GIFT-COFB AEAD" << std::endl << std::endl;
  std::cout << "Key       : " << to_hex(key, sizeof(key)) << std::endl;
  std::cout << "Nonce     : " << to_hex(nonce, sizeof(nonce)) << std::endl;
  std::cout << "Text      : " << to_hex(txt, sizeof(txt)) << std::endl;
  std::cout << "Encrypted : " << to_hex(enc, sizeof(enc)) << std::endl;
  std::cout << "Tag       : " << to_hex(tag, sizeof(tag)) << std::endl;
  std::cout << "Decrypted : " << to_hex(dec, sizeof(dec)) << std::endl;

  return EXIT_SUCCESS;
}
