#!/usr/bin/python3

import gift_cofb
import numpy as np
from random import Random, randint

u8 = np.uint8


def test_gift_cofb_kat():
    """
    Tests functional correctness of GIFT-COFB AEAD implementation, using
    Known Answer Tests submitted along with final round submission of GIFT-COFB
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(len(key) >> 1, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(len(nonce) >> 1, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = gift_cofb.encrypt(key, nonce, ad, pt)
            flag, text = gift_cofb.decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[GIFT-COFB KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x${(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[GIFT-COFB KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def flip_bit(inp: bytes) -> bytes:
    """
    Randomly selects a byte offset of a given byte array ( inp ), whose single random bit
    will be flipped. Input is **not** mutated & single bit flipped byte array is returned back.

    Taken from https://github.com/itzmeanjan/elephant/blob/2a21c7e/wrapper/python/test_elephant.py#L217-L237
    """
    arr = bytearray(inp)
    ilen = len(arr)

    idx = randint(0, ilen - 1)
    bidx = randint(0, 7)

    mask0 = (0xFF << (bidx + 1)) & 0xFF
    mask1 = (0xFF >> (8 - bidx)) & 0xFF
    mask2 = 1 << bidx

    msb = arr[idx] & mask0
    lsb = arr[idx] & mask1
    bit = (arr[idx] & mask2) >> bidx

    arr[idx] = msb | ((1 - bit) << bidx) | lsb
    return bytes(arr)


def test_gift_cofb_auth_fail():
    """
    Test that GIFT-COFB authentication failure happens when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is explicitly zeroed.
    """
    rng = Random()

    DLEN = 32
    CTLEN = 64

    key = rng.randbytes(16)
    nonce = rng.randbytes(16)
    data = rng.randbytes(DLEN)
    txt = rng.randbytes(CTLEN)

    enc, tag = gift_cofb.encrypt(key, nonce, data, txt)

    # case 0
    data_ = flip_bit(data)
    flg, dec = gift_cofb.decrypt(key, nonce, tag, data_, enc)

    assert not flg, "GIFT-COFB authentication must fail !"
    assert bytes(CTLEN) == dec, "Unverified plain text must not be released !"

    # case 1
    enc_ = flip_bit(enc)
    flg, dec = gift_cofb.decrypt(key, nonce, tag, data, enc_)

    assert not flg, "GIFT-COFB authentication must fail !"
    assert bytes(CTLEN) == dec, "Unverified plain text must not be released !"

    # case 2
    flg, dec = gift_cofb.decrypt(key, nonce, tag, data_, enc_)

    assert not flg, "GIFT-COFB authentication must fail !"
    assert bytes(CTLEN) == dec, "Unverified plain text must not be released !"


if __name__ == "__main__":
    print("Execute test cases using `pytest`")
