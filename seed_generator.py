#!/usr/bin/env python3

import os
import json
import base64
import hashlib

from mnemonic import Mnemonic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bip_utils import (
    Bip39SeedGenerator,
    Bip32Slip10Secp256k1,
    WifEncoder,              # only this, no WifVersion
)

# Your native-SegWit multisig account path (BIP-48)
MULTISIG_PATH = "m/48'/0'/0'/2'"
# Then we’ll encrypt the first external child at …/0/0
WIF_DERIV_PATH = MULTISIG_PATH + "/0/0"


def generate_mnemonic() -> str:
    return Mnemonic("english").to_mnemonic(os.urandom(32))


def encrypt_wif(wif: str, aes_key: bytes) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, wif.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def main():
    # 1) New 24-word seed
    mnemonic = generate_mnemonic()

    # 2) Master node from seed
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    root = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    # 3) Master fingerprint = first 4 bytes of RIPEMD160(SHA256(root_pub))
    root_pub_bytes = root.PublicKey().RawCompressed().ToBytes()
    fp = hashlib.new("ripemd160", hashlib.sha256(root_pub_bytes).digest()).digest()[:4]

    # 4) Derive the multisig account node
    acct = root.DerivePath(MULTISIG_PATH)
    xpub = acct.PublicKey().ToExtended()
    pubkey = acct.PublicKey().RawCompressed().ToHex()

    # 5) Derive first external child and get its WIF
    child = root.DerivePath(WIF_DERIV_PATH)
    priv_bytes = child.PrivateKey().Raw().ToBytes()
    wif = WifEncoder.Encode(priv_bytes)  # defaults to mainnet + compressed pubkey  [oai_citation:0‡bip-utils.readthedocs.io](https://bip-utils.readthedocs.io/en/latest/bip_utils/wif/wif.html)

    # 6) Encrypt WIF
    aes_key = os.urandom(32)
    encrypted_wif = encrypt_wif(wif, aes_key)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    # 7) Print everything
    print("MANAGED_KEY_ENC (Encrypted WIF, base64):")
    print(encrypted_wif)
    print("\nSIGNER_KEY_SECRET (AES-256 Key, base64):")
    print(aes_key_b64)

    print(f"\nMASTER_FINGERPRINT (hex): {fp.hex()}")
    print(f"DERIVATION_PATH:        {MULTISIG_PATH}")
    print(f"XPUB (account-level):   {xpub}")
    print(f"PUBKEY (at {MULTISIG_PATH}): {pubkey}")

    print("\n🔐 Mnemonic (BACK THIS UP SECURELY, DO NOT STORE IN APP):")
    print(mnemonic)


if __name__ == "__main__":
    main()