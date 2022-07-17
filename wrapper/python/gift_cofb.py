#!/usr/bin/python3

"""
  Before using `gift_cofb` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/gift-cofb
"""

from typing import Tuple
from ctypes import c_size_t, CDLL, c_bool
import numpy as np
from posixpath import exists, abspath

SO_PATH: str = abspath("../libgift_cofb.so")
assert exists(SO_PATH), "Use `make lib` to generate shared library object !"

SO_LIB: CDLL = CDLL(SO_PATH)

u8 = np.uint8
len_t = c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags="CONTIGUOUS")
bool_t = c_bool


def gift_cofb_encrypt(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts M ( >=0 ) -bytes plain text, with GIFT-COFB AEAD,
    while using 16 -bytes secret key, 16 -bytes public message nonce &
    N ( >=0 ) -bytes associated data, while producing M -bytes cipher text
    & 16 -bytes authentication tag ( in order )
    """
    assert len(key) == 16, "GIFT-COFB takes 16 -bytes secret key !"
    assert len(nonce) == 16, "GIFT-COFB takes 16 -bytes nonce !"

    ad_len = len(data)
    ct_len = len(text)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    text_ = np.frombuffer(text, dtype=u8)
    enc = np.empty(ct_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, len_t, uint8_tp, uint8_tp, len_t, uint8_tp]
    SO_LIB.gift_cofb_encrypt.argtypes = args

    SO_LIB.gift_cofb_encrypt(key_, nonce_, data_, ad_len, text_, enc, ct_len, tag)

    enc_ = enc.tobytes()
    tag_ = tag.tobytes()

    return enc_, tag_


def gift_cofb_decrypt(
    key: bytes, nonce: bytes, tag: bytes, data: bytes, enc: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts M ( >=0 ) -bytes cipher text, with GIFT-COFB AEAD,
    while using 16 -bytes secret key, 16 -bytes public message nonce,
    16 -bytes authentication tag & N ( >=0 ) -bytes associated data, while
    producing boolean flag denoting verification status ( which must hold truth
    value, check before consuming decrypted output bytes ) & M -bytes
    plain text ( in order )
    """
    assert len(key) == 16, "GIFT-COFB takes 16 -bytes secret key !"
    assert len(nonce) == 16, "GIFT-COFB takes 16 -bytes nonce !"
    assert len(tag) == 16, "GIFT-COFB takes 16 -bytes authentication tag !"

    ad_len = len(data)
    ct_len = len(enc)

    key_ = np.frombuffer(key, dtype=u8)
    nonce_ = np.frombuffer(nonce, dtype=u8)
    tag_ = np.frombuffer(tag, dtype=u8)
    data_ = np.frombuffer(data, dtype=u8)
    enc_ = np.frombuffer(enc, dtype=u8)
    dec = np.empty(ct_len, dtype=u8)

    args = [uint8_tp, uint8_tp, uint8_tp, uint8_tp, len_t, uint8_tp, uint8_tp, len_t]
    SO_LIB.gift_cofb_decrypt.argtypes = args
    SO_LIB.gift_cofb_decrypt.restype = bool_t

    f = SO_LIB.gift_cofb_decrypt(key_, nonce_, tag_, data_, ad_len, enc_, dec, ct_len)

    dec_ = dec.tobytes()

    return f, dec_


if __name__ == "__main__":
    print("Use `gift_cofb` as library module")
