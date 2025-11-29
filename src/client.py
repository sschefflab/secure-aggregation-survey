#!/usr/bin/env python3
"""HTTP client for Flask server, sends JSON via POST for 4 rounds."""
import requests
import argparse
import time
from config import ROUNDS, DEBUG

# Advertise keys imports
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from _client_helper import pubkey_to_b64, privkey_to_b64

SERVER_URL = 'http://127.0.0.1:5000/round'

class Client:
	def __init__(self, client_id: int):
		self.client_id = client_id
		self.key_c_pub = None
		self.key_c_sec = None
		self.key_s_pub = None
		self.key_s_sec = None
		#self.round_last_completed = -1
		#self.server_url = server_url
		#self.session = requests.Session()

	def advertise_keys(self):
		self.key_c_sec = X25519PrivateKey.generate()
		self.key_c_pub = self.key_c_sec.public_key()

		self.key_s_sec = X25519PrivateKey.generate()
		self.key_s_pub = self.key_s_sec.public_key()

		return {
			'client_id': self.client_id,
			'round': 1,
			'payload': {
				'key_c_pub': pubkey_to_b64(self.key_c_pub),
				'key_s_pub': pubkey_to_b64(self.key_s_pub)
			}
		}
#		return {
#			'client_id': self.client_id,
#			'payload': {
#				'key_c_pub': "asdf",
#				'key_s_pub': "jkl;"
#			}
#		}

	def share_keys(self, keys_from_server):
		pass

	def masked_input_collection(self, ciphertexts_from_server):
		pass

	def unmasking(self, users_from_server):
		pass





def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--id', type=int, required=True, help='Client id (1..i for testing)')
	args = parser.parse_args()
	client_id = args.id

	# Setup: Initialize client
	client = Client(client_id=client_id)

	# Round 1: Advertise Keys
	r1_payload = client.advertise_keys()
	# include round number in the JSON body
	r1_payload['round'] = 1
	r1_resp = requests.post(SERVER_URL, json=r1_payload)

	if DEBUG:
		print(f"Client keys after round 1:\nkey_c_sec:{privkey_to_b64(client.key_c_sec)}\nkey_c_pub:{pubkey_to_b64(client.key_c_pub)}\nkey_s_sec:{privkey_to_b64(client.key_s_sec)}\nkey_s_pub:{pubkey_to_b64(client.key_s_pub)}")

	for round in range(2, ROUNDS+1):
		payload = {'client_id': client_id, 'round': round, 'payload': f'Hello from client {client_id} round {round}'}
		resp = requests.post(SERVER_URL, json=payload)
		print(f"Client {client_id} round {round} sent: {payload}")
		print(f"Client {client_id} round {round} got: {resp.json()}")
		time.sleep(0.2)

if __name__ == '__main__':
	main()
