#!/usr/bin/env python3
import argparse
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_keys(n):
    output_dir = "keys"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    all_verification_keys = {}
    for i in range(1, n+1):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(os.path.join(output_dir, f"sign-{i}.key"), "wb") as f:
            f.write(priv_bytes)

        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        all_verification_keys[i] = pub_bytes.hex()

        print(f"Generated keys for client {i}")

    with open(os.path.join(output_dir, "verification_keys.json"), "w") as f:
        json.dump(all_verification_keys, f, indent=4)

    print(f"keys saved in '{output_dir}/'")
    print("Distribute one 'sign-X.key' to each client and 'allverify.key' to everyone.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline PKI Key Generator for SecAgg.")
    parser.add_argument('--N', type=int, required=True, help='Number of clients to generate keys for')
    args = parser.parse_args()
    generate_keys(args.N)