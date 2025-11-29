from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import base64
import requests
import time
from config import DEBUG, R1_POLL_INTERVAL, R1_MAX_POLLS

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