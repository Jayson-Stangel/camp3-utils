#!/usr/bin/env python3

import os
import base64
import argparse
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1

# BIP-48 multisig account path
MULTISIG_PATH = "m/48'/0'/0'/2'"
# First external child index path
WIF_DERIV_PATH = MULTISIG_PATH + "/0/0"

def generate_mnemonic() -> str:
    return Mnemonic("english").to_mnemonic(os.urandom(32))

def encrypt_wif(wif: str, aes_key: bytes) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, wif.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def main():
    parser = argparse.ArgumentParser(
        description="Generate or use mnemonic and encryption key to output xprv and encrypted WIF."
    )
    parser.add_argument(
        "--mnemonic", type=str, default="", help="24-word mnemonic (leave blank to generate)"
    )
    parser.add_argument(
        "--encrypt-key", type=str, default="", help="Base64 AES-256 key (leave blank to generate)"
    )
    args = parser.parse_args()

    # 1) Mnemonic
    mnemonic = args.mnemonic.strip() or generate_mnemonic()

    # 2) Master seed → root
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    root = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    # 3) Account node
    acct = root.DerivePath(MULTISIG_PATH)
    xprv = acct.PrivateKey().ToExtended()

    # 4) First external child WIF
    child = root.DerivePath(WIF_DERIV_PATH)
    wif = child.PrivateKey().ToWif()

    # 5) AES key
    if args.encrypt_key.strip():
        aes_key = base64.b64decode(args.encrypt_key.strip())
    else:
        aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(aes_key).decode()

    # 6) Encrypt WIF
    encrypted_wif = encrypt_wif(wif, aes_key)

    # 7) Output everything
    print("MNEMONIC:", mnemonic)
    print("MASTER_XPRV:", xprv)
    print("ENCRYPTION_KEY:", aes_key_b64)
    print("ENCRYPTED_WIF:", encrypted_wif)

if __name__ == "__main__":
    main()