#!/usr/bin/env python3
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Random import get_random_bytes
import base64
import requests
import time
import re
from config import (
    DEBUG,
    DERIVED_KEY_LENGTH,
    MAX_POLLS,
    POLL_INTERVALS,
    DEBUG_TESTING_DELAY,
    DEBUG_TESTING_DELAY_TIME,
    DEBUG_TESTING_DELAY_CLIENT_ID,
    DEBUG_TESTING_DELAY_ROUND,
)
from config import FIELD_ELEMENT_SIZE, R


def bytes_to_field_element(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big") % R


def field_elements_to_bytes(x: int) -> bytes:
    return (x % R).to_bytes(FIELD_ELEMENT_SIZE, byteorder="big")


def field_negate(x: int) -> int:
    return (R - x) % R


def field_add(a: int, b: int) -> int:
    return (a + b) % R


def prg_block_to_field_elements(prg_block: bytes, vec_len: int) -> list[int]:
    return [
        bytes_to_field_element(
            prg_block[j * FIELD_ELEMENT_SIZE : (j + 1) * FIELD_ELEMENT_SIZE]
        )
        for j in range(vec_len)
    ]


def pubkey_to_bytes(pubkey: X25519PublicKey) -> bytes:
    return pubkey.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def pubkey_to_b64(pubkey: X25519PublicKey) -> str:
    pubkey_raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pubkey_raw).decode("ascii")


def b64_to_pubkey(b64_str: str) -> X25519PublicKey:
    pubkey_decoded = base64.b64decode(b64_str.encode("ascii"))
    return X25519PublicKey.from_public_bytes(pubkey_decoded)


def privkey_to_raw_bytes(privkey: X25519PrivateKey) -> bytes:
    privkey_raw = privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),  # do not encrypt the key for debugging
    )
    return privkey_raw


def privkey_to_b64(privkey: X25519PrivateKey) -> str:
    privkey_raw = privkey_to_raw_bytes(privkey)
    return base64.b64encode(privkey_raw).decode("ascii")


def b64_to_privkey(b64_str: str) -> X25519PrivateKey:
    privkey_decoded = base64.b64decode(b64_str.encode("ascii"))
    return X25519PrivateKey.from_private_bytes(privkey_decoded)


def _poll_for_round1_result(client_id: int, server_url: str) -> dict:
    """Poll server for round 1 result.  Result response from server, or None if timeout"""
    print(f"Client {client_id}: Polling for round 1 result...", flush=True)
    for poll_count in range(MAX_POLLS[1]):
        try:
            result_resp = requests.get(
                f"{server_url}/round1/result?client_id={client_id}", timeout=5
            )
            if result_resp.status_code == 200:
                print(
                    f"Client {client_id}: Got round 1 result after {poll_count} polls",
                    flush=True,
                )
                return result_resp.json()
        except requests.exceptions.Timeout:
            pass  # Continue polling
        except requests.exceptions.RequestException as e:
            print(f"Client {client_id}: Error polling: {e}", flush=True)

        time.sleep(POLL_INTERVALS[1])

    print(f"Client {client_id}: Timeout waiting for round 1 result", flush=True)
    return None


def _poll_for_round2_result(client_id: int, server_url: str) -> dict:
    """Poll server for round 2 result"""
    print(f"Client {client_id}: Polling for round 2 result...", flush=True)
    for poll_count in range(MAX_POLLS[2]):
        try:
            result_resp = requests.get(
                f"{server_url}/round2/result?client_id={client_id}", timeout=5
            )
            if result_resp.status_code == 200:
                print(
                    f"Client {client_id}: Got round 2 result after {poll_count} polls",
                    flush=True,
                )
                return result_resp.json()
        except requests.exceptions.Timeout:
            pass  # Continue polling
        except requests.exceptions.RequestException as e:
            print(f"Client {client_id}: Error polling: {e}", flush=True)

        time.sleep(POLL_INTERVALS[2])

    print(f"Client {client_id}: Timeout waiting for round 2 result", flush=True)
    return None


def _poll_for_round3_result(client_id: int, server_url: str) -> dict:
    """Poll server for round 3 result"""
    print(f"Client {client_id}: Polling for round 3 result...", flush=True)
    for poll_count in range(MAX_POLLS[3]):
        try:
            result_resp = requests.get(
                f"{server_url}/round3/result?client_id={client_id}", timeout=5
            )
            if result_resp.status_code == 200:
                print(
                    f"Client {client_id}: Got round 3 result after {poll_count} polls",
                    flush=True,
                )
                return result_resp.json()
        except requests.exceptions.Timeout:
            pass  # Continue polling
        except requests.exceptions.RequestException as e:
            print(f"Client {client_id}: Error polling: {e}", flush=True)

        time.sleep(POLL_INTERVALS[3])

    print(f"Client {client_id}: Timeout waiting for round 3 result", flush=True)
    return None


def _poll_for_round4_result(client_id: int, server_url: str) -> dict:
    """Poll server for round 4 result"""
    print(f"Client {client_id}: Polling for round 4 result...", flush=True)
    for poll_count in range(MAX_POLLS[4]):
        try:
            result_resp = requests.get(
                f"{server_url}/round4/result?client_id={client_id}", timeout=5
            )
            if result_resp.status_code == 200:
                print(
                    f"Client {client_id}: Got round 4 result after {poll_count} polls",
                    flush=True,
                )
                return result_resp.json()
        except requests.exceptions.Timeout:
            pass  # Continue polling
        except requests.exceptions.RequestException as e:
            print(f"Client {client_id}: Error polling: {e}", flush=True)
        time.sleep(POLL_INTERVALS[4])
    print(f"Client {client_id}: Timeout waiting for round 4 result", flush=True)
    return None


def _poll_for_round5_result(client_id: int, server_url: str) -> dict:
    """Poll server for round 5 result"""
    print(f"Client {client_id}: Polling for round 5 result...", flush=True)
    for poll_count in range(MAX_POLLS[5]):
        try:
            result_resp = requests.get(
                f"{server_url}/round5/result?client_id={client_id}", timeout=5
            )
            if result_resp.status_code == 200:
                print(
                    f"Client {client_id}: Got round 5 result after {poll_count} polls",
                    flush=True,
                )
                return result_resp.json()
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException as e:
            print(f"Client {client_id}: Error polling: {e}", flush=True)
        time.sleep(POLL_INTERVALS[5])
    print(f"Client {client_id}: Timeout waiting for round 5 result", flush=True)
    return None


def do_round(client_id: int, round: int, payload: dict, server_url: str) -> dict:
    if (
        DEBUG_TESTING_DELAY
        and client_id == DEBUG_TESTING_DELAY_CLIENT_ID
        and round == DEBUG_TESTING_DELAY_ROUND
    ):
        print(
            f"Client {client_id}: Delaying before sending round {round}...", flush=True
        )
        time.sleep(DEBUG_TESTING_DELAY_TIME)

    print(f"Client {client_id}: Sending round {round} payload: {payload}", flush=True)
    round_resp = requests.post(f"{server_url}/round/{round}", json=payload)
    print(
        f"Client {client_id}: Round {round} immediate response: {round_resp.json()}",
        flush=True,
    )

    result = poll_for_round_result(client_id, round, server_url)
    return result


def poll_for_round_result(client_id: int, round: int, server_url: str) -> dict:
    if round == 1:
        return _poll_for_round1_result(client_id, server_url)
    elif round == 2:
        return _poll_for_round2_result(client_id, server_url)
    elif round == 3:
        return _poll_for_round3_result(client_id, server_url)
    elif round == 4:
        return _poll_for_round4_result(client_id, server_url)
    elif round == 5:
        return _poll_for_round5_result(client_id, server_url)
    else:
        print(
            f"Client {client_id}: No polling implemented for round {round}", flush=True
        )
        return {}


def derive_shared_key(
    client_id: int,
    other_id: int,
    self_c_sec: X25519PrivateKey,
    other_c_pub: X25519PublicKey,
) -> bytes:
    shared_key = self_c_sec.exchange(other_c_pub)
    id_low, id_high = min(client_id, other_id), max(client_id, other_id)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,
        info=b"key-agreement-pair-"
        + str(id_low).encode("ascii")
        + b"-"
        + str(id_high).encode("ascii"),
    ).derive(shared_key)
    return derived_key


def make_prg(
    client_id: int,
    other_id: int,
    self_s_sec: X25519PrivateKey,
    other_s_pub: X25519PublicKey,
    vec_len: int,
) -> bytes:
    shared_key = self_s_sec.exchange(other_s_pub)
    id_low, id_high = min(client_id, other_id), max(client_id, other_id)
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=vec_len * FIELD_ELEMENT_SIZE,
        info=b"prg-pair-"
        + str(id_low).encode("ascii")
        + b"-"
        + str(id_high).encode("ascii"),
    ).derive(shared_key)


def make_prg2(client_id: int, other_id: int, prg_seed: bytes, vec_len: int) -> bytes:
    PRG_block = HKDF(
        algorithm=hashes.SHA256(),
        length=vec_len * FIELD_ELEMENT_SIZE,
        salt=None,
        info=b"prg-seed-self"
        + str(client_id).encode("ascii")
        + b"-other"
        + str(other_id).encode("ascii"),
    ).derive(prg_seed)
    return PRG_block


def encrypt_with_derived_key(
    derived_key: bytes, plaintext: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(derived_key)
    nonce = get_random_bytes(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_with_derived_key(
    derived_key: bytes, nonce: bytes, ciphertext: bytes, associated_data
) -> bytes:
    """
    Decrypt ciphertext with the same AES-GCM key and nonce.
    Raises InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext


def ids_to_associated_data(from_id: int, to_id: int) -> bytes:
    return f"from:{from_id},to:{to_id}".encode("ascii")


def associated_data_to_ids(associated_data: bytes) -> tuple[int, int]:
    match = re.search(r"from:([0-9]+),to:([0-9]+)", associated_data.decode("ascii"))
    if match:
        return int(match.group(1)), int(match.group(2))
    raise ValueError(
        f"Invalid associated_data format, unable to extract from and to from {associated_data.decode('ascii')}"
    )


def bencode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def bdecode_to_bytes(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def bdecode(data_b64: str) -> bytes:
    return bdecode_to_bytes(data_b64)


def bdecode_to_str(data_b64: str) -> str:
    return base64.b64decode(data_b64.encode("ascii")).decode("utf-8")


def jencode_to_bytes(json_data: dict) -> bytes:
    return json.dumps(json_data).encode("utf-8")


def bytes_to_json(data_bytes: bytes) -> dict:
    return json.loads(data_bytes.decode("utf-8"))


def jdecode_from_bytes(data_bytes: bytes) -> dict:
    return bytes_to_json(data_bytes)


def jencode_to_b64str(json_data: dict) -> str:
    return bencode(json.dumps(json_data).encode("utf-8"))


def b64str_to_json(data_b64_str: str) -> dict:
    return bytes_to_json(bdecode_to_bytes(data_b64_str))


def jencode_ciphertexts_for_other_r1r_r2(ciphertexts_for_other_r1r_r2: dict) -> dict:
    return {
        r1r: (bencode(nonce), bencode(ciphertext))
        for (r1r, (nonce, ciphertext)) in ciphertexts_for_other_r1r_r2.items()
    }  # Placeholder


def jdecode_ciphertexts(nonce_b64, ciphertext_b64) -> tuple[bytes, bytes]:
    return (bdecode(nonce_b64), bdecode(ciphertext_b64))
