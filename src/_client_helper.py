from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import base64
from SETUP import DEBUG

def pubkey_to_b64(pubkey: X25519PublicKey) -> str:
    pubkey_raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pubkey_raw).decode('ascii')

def b64_to_pubkey(b64_str: str) -> X25519PublicKey:
    pubkey_decoded = base64.b64decode(b64_str.encode('ascii'))
    return X25519PublicKey.from_public_bytes(pubkey_decoded)

def privkey_to_b64(privkey: X25519PrivateKey) -> str:
    assert(DEBUG) # don't ever want to print priv key if not debugging
    privkey_raw = privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption() # do not encrypt the key for debugging
    )
    return base64.b64encode(privkey_raw).decode('ascii')

def b64_to_privkey(b64_str: str) -> X25519PrivateKey:
    privkey_decoded = base64.b64decode(b64_str.encode('ascii'))
    return X25519PrivateKey.from_private_bytes(privkey_decoded)