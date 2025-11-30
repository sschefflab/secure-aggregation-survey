#!/usr/bin/env python3
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Random import get_random_bytes
import base64
import requests
import time
import re
from config import DEBUG, R1_POLL_INTERVAL, R1_MAX_POLLS, DERIVED_KEY_LENGTH, R1_MAX_POLLS, R1_THRESHOLD_WAIT, R2_MAX_POLLS, R2_SERVER_WAIT, R2_POLL_INTERVAL


def pubkey_to_b64(pubkey: X25519PublicKey) -> str:
    pubkey_raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pubkey_raw).decode('ascii')

def b64_to_pubkey(b64_str: str) -> X25519PublicKey:
    pubkey_decoded = base64.b64decode(b64_str.encode('ascii'))
    return X25519PublicKey.from_public_bytes(pubkey_decoded)

def privkey_to_raw_bytes(privkey: X25519PrivateKey) -> bytes:
    privkey_raw = privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption() # do not encrypt the key for debugging
    )
    return privkey_raw

def privkey_to_b64(privkey: X25519PrivateKey) -> str:
    privkey_raw = privkey_to_raw_bytes(privkey)
    return base64.b64encode(privkey_raw).decode('ascii')

def b64_to_privkey(b64_str: str) -> X25519PrivateKey:
    privkey_decoded = base64.b64decode(b64_str.encode('ascii'))
    return X25519PrivateKey.from_private_bytes(privkey_decoded)


def poll_for_round1_result(client_id: int, server_url: str) -> dict:
	"""Poll server for round 1 result.  Result response from server, or None if timeout"""
	print(f"Client {client_id}: Polling for round 1 result...", flush=True)
	for poll_count in range(R1_MAX_POLLS):
		try:
			result_resp = requests.get(f"{server_url}/round1/result?client_id={client_id}", timeout=5)
			if result_resp.status_code == 200:
				print(f"Client {client_id}: Got round 1 result after {poll_count} polls", flush=True)
				return result_resp.json()
		except requests.exceptions.Timeout:
			pass  # Continue polling
		except requests.exceptions.RequestException as e:
			print(f"Client {client_id}: Error polling: {e}", flush=True)
		
		time.sleep(R1_POLL_INTERVAL)
	
	print(f"Client {client_id}: Timeout waiting for round 1 result", flush=True)
	return None

def poll_for_round2_result(client_id: int, server_url: str) -> dict:
	"""Poll server for round 2 result"""
	print(f"Client {client_id}: Polling for round 2 result...", flush=True)
	for poll_count in range(R2_MAX_POLLS):
		try:
			result_resp = requests.get(f"{server_url}/round2/result?client_id={client_id}", timeout=5)
			if result_resp.status_code == 200:
				print(f"Client {client_id}: Got round 2 result after {poll_count} polls", flush=True)
				return result_resp.json()
		except requests.exceptions.Timeout:
			pass  # Continue polling
		except requests.exceptions.RequestException as e:
			print(f"Client {client_id}: Error polling: {e}", flush=True)
		
		time.sleep(R2_POLL_INTERVAL)
	
	print(f"Client {client_id}: Timeout waiting for round 2 result", flush=True)
	return None

def round1(client_id: int, r1_payload: dict, server_url: str, testing_delay=False):
	# DEBUG TEST ONLY -- If we are testing delayed responses, sleep here
	if testing_delay:
		print(f"DEBUG: Delaying client {client_id} round 1 key advertisement by 3 seconds")
		time.sleep(3)

	print(f"Client {client_id}: Round 1 POST payload: {r1_payload}", flush=True)
	r1_resp = requests.post(f"{server_url}/round/1", json=r1_payload)
	print(f"Client {client_id}: Round 1 immediate response: {r1_resp.json()}", flush=True)

    # Poll for round 1 result
	result = poll_for_round1_result(client_id, server_url)
	return result

def derive_shared_key(client_id: int, other_id: int, self_c_sec: X25519PrivateKey, other_c_pub: X25519PublicKey) -> bytes:
    shared_key = self_c_sec.exchange(other_c_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,
        info=b'key-agreement-self'+str(client_id).encode('ascii')+b'-other'+str(other_id).encode('ascii'),
    ).derive(shared_key)
    return derived_key

def encrypt_with_derived_key(derived_key: bytes, plaintext: bytes,
                             associated_data: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(derived_key)
    nonce = get_random_bytes(12) # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_with_derived_key(derived_key: bytes, nonce: bytes, ciphertext: bytes,
                             associated_data) -> bytes:
    """
    Decrypt ciphertext with the same AES-GCM key and nonce.
    Raises InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext

def ids_to_associated_data(from_id: int, to_id: int) -> bytes:
    return f"from:{from_id},to:{to_id}".encode('ascii')

def associated_data_to_ids(associated_data: bytes) -> tuple[int, int]:
    match = re.search(r"from:([0-9]+),to:([0-9]+)", associated_data.decode('ascii'))
    if match:
        return int(match.group(1)), int(match.group(2))
    raise ValueError(f"Invalid associated_data format, unable to extract from and to from {associated_data.decode('ascii')}")

def bencode(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')

def bdecode_to_bytes(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode('ascii'))

def bdecode(data_b64: str) -> bytes:
    return bdecode_to_bytes(data_b64)

def bdecode_to_str(data_b64: str) -> str:
    return base64.b64decode(data_b64.encode('ascii')).decode('utf-8')

def jencode_to_bytes(json_data: dict) -> bytes:
    return json.dumps(json_data).encode('utf-8')

def bytes_to_json(data_bytes: bytes) -> dict:  
    return json.loads(data_bytes.decode('utf-8'))

def jencode_to_b64str(json_data: dict) -> str:
    return bencode(json.dumps(json_data).encode('utf-8'))

def b64str_to_json(data_b64_str: str) -> dict:  
    return bytes_to_json(bdecode_to_bytes(data_b64_str))

def jencode_ciphertexts_for_other_r1r_r2(ciphertexts_for_other_r1r_r2: dict) -> dict:
    return {r1r: (bencode(nonce), bencode(ciphertext)) for (r1r, (nonce, ciphertext)) in ciphertexts_for_other_r1r_r2.items()}  # Placeholder

def jdecode_ciphertexts(nonce_b64, ciphertext_b64) -> tuple[bytes,bytes]:
    return (bdecode(nonce_b64), bdecode(ciphertext_b64))