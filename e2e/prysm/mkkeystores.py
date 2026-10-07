#!/usr/bin/env python3
# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

"""Writes the EIP-2335 keystores in keys/ for the deterministic "interop"
validator keys that `prysmctl testnet generate-genesis --num-validators=N`
puts into a genesis state (the keys of the consensus-specs interop
test vectors, index i has secret int(sha256(i)) mod the curve order).

These keys are intentionally public and are not a security risk.  They are
only usable on a throwaway localnet that was started from a genesis state
containing them.  Note to security researchers: the presence of these keys
is intentional, please do not report them.

Usage: pip install py_ecc pycryptodome; ./mkkeystores.py keys 64 hemi-localnet
"""

import hashlib
import json
import os
import sys
import uuid

from Crypto.Cipher import AES
from Crypto.Util import Counter
from py_ecc.bls import G2ProofOfPossession as bls

CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def interop_secret(index: int) -> int:
    digest = hashlib.sha256(index.to_bytes(32, "little")).digest()
    return int.from_bytes(digest, "little") % CURVE_ORDER


def keystore(secret: int, password: str, index: int) -> dict:
    sk = secret.to_bytes(32, "big")
    # a deterministic salt and iv, so that the files do not change between runs
    salt = hashlib.sha256(b"salt" + sk).digest()
    iv = hashlib.sha256(b"iv" + sk).digest()[:16]
    count = 262144
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, count, dklen=32)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(dk[:16], AES.MODE_CTR, counter=ctr).encrypt(sk)
    return {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {"dklen": 32, "c": count, "prf": "hmac-sha256", "salt": salt.hex()},
                "message": "",
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": hashlib.sha256(dk[16:32] + cipher).hexdigest(),
            },
            "cipher": {"function": "aes-128-ctr", "params": {"iv": iv.hex()}, "message": cipher.hex()},
        },
        "description": "interop validator %d" % index,
        "pubkey": bls.SkToPk(secret).hex(),
        "path": "",
        "uuid": str(uuid.UUID(bytes=hashlib.sha256(b"uuid" + sk).digest()[:16], version=4)),
        "version": 4,
    }


def main() -> None:
    out, count, password = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    os.makedirs(out, exist_ok=True)
    for i in range(count):
        with open(os.path.join(out, "keystore-interop-%02d.json" % i), "w") as f:
            json.dump(keystore(interop_secret(i), password, i), f, indent=1)
            f.write("\n")


if __name__ == "__main__":
    main()
