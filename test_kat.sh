#!/bin/bash

# Script for ease of execution of Known Answer Tests against GIFT-COFB implementation

make lib

# ---

mkdir -p tmp
pushd tmp

wget -O gift_cofb.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/gift-cofb.zip
unzip gift_cofb.zip

cp gift-cofb/Implementations/crypto_aead/giftcofb128v1/LWC_AEAD_KAT_128_128.txt ../

popd

# ---

rm -rf tmp
mv LWC_AEAD_KAT_128_128.txt wrapper/python/

# ---

pushd wrapper/python

python3 -m pytest -v
rm LWC_*_KAT_*.txt

popd

# ---
