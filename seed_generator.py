#!/usr/bin/env python3

import os
import base64
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes


def generate_mnemonic() -> str:
    mnemo = Mnemonic("english")
    entropy = os.urandom(32)  # 256-bit entropy = 24 words
    return mnemo.to_mnemonic(entropy)


def derive_wif_from_mnemonic(mnemonic: str) -> str:
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
    priv_key_obj = (
        bip84_ctx
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
        .PrivateKey()
    )
    return priv_key_obj.ToWif()


def encrypt_wif(wif: str, aes_key: bytes) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    encrypted = aesgcm.encrypt(nonce, wif.encode(), None)
    return base64.b64encode(nonce + encrypted).decode()


def main():
    # Step 1: Generate 24-word mnemonic
    mnemonic = generate_mnemonic()

    # Step 2: Derive WIF and XPUB at m/84'/0'/0'
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)

    # Get WIF at m/84'/0'/0'/0/0
    wif = (
        bip84_ctx
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
        .PrivateKey()
        .ToWif()
    )

    # Get XPUB at m/84'/0'/0'
    xpub = bip84_ctx.Purpose().Coin().Account(0).PublicKey().ToExtended()

    # Step 3: Generate AES key
    aes_key = os.urandom(32)

    # Step 4: Encrypt WIF
    encrypted_wif_b64 = encrypt_wif(wif, aes_key)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    # Step 5: Output
    print("MANAGED_KEY_ENC (Encrypted WIF, base64):")
    print(encrypted_wif_b64)
    print("\nSIGNER_KEY_SECRET (AES-256 Key, base64):")
    print(aes_key_b64)
    print("\nXPUB (m/84'/0'/0'):")
    print(xpub)
    print("\n🔐 Mnemonic (DO NOT store in app, back this up securely):")
    print(mnemonic)


if __name__ == "__main__":
    main()