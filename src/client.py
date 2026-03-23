#!/usr/bin/env python3
import base64
import requests
import argparse
import time
import json
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from config import ROUNDS, THRESHOLD_CLIENTS, PRG_SEED_SIZE, DEBUG, DEBUG_TESTING_DELAY, FIELD_ELEMENT_SIZE, R
from _client_helper import bencode, bdecode, field_add, field_negate, jencode_to_bytes, jdecode_from_bytes, jencode_ciphertexts_for_other_r1r_r2, jdecode_ciphertexts, pubkey_to_b64, b64_to_pubkey, privkey_to_raw_bytes, do_round
from _client_helper import derive_shared_key, encrypt_with_derived_key, decrypt_with_derived_key, ids_to_associated_data, make_prg, make_prg2, prg_block_to_field_elements, field_negate, field_add


SERVER_URL = 'http://127.0.0.1:5000'


class SecureAggregationClient:
   def __init__(self, client_id: int, x_u: list[int]):
       self.client_id = client_id
       self.x_u = x_u
       self.key_c_pub = None
       self.key_c_sec = None
       self.key_s_pub = None
       self.key_s_sec = None
       self.round1_responders = list() # is a list because we need consistent indexing
       self.pubkeys_for_r1r = {}
       self.symmkeys_for_other_r1r = {}
       self.s_sec_shares = None
       self.prg_seed = None
       self.prg_seed_shares = None
       self.p_u_v = {}
       self.p_u = None
       self.round2_responders = list()
       # Shares received from other users (decrypted in Round 3, used in Round 4)
       self.received_s_sec_shares = {}   # {sender_id: ((x1, y1), (x2, y2))}
       self.received_prg_seed_shares = {} # {sender_id: (x, y)}


   def advertise_keys(self) -> dict:
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


   def share_keys(self, r1_response: dict) -> dict:


       # Set clients that responded in r1 and their keys
       self.round1_responders = [int(r1r_str) for r1r_str in r1_response.keys()]
       self.pubkeys_for_r1r = {int(r1r_str): r1_response[r1r_str] for r1r_str in r1_response.keys()} # dict with int keys instead of str


       # Verify uniqueness of keys
       all_c_pub = {self.pubkeys_for_r1r[r1r]["key_c_pub"] for r1r in self.round1_responders}
       all_s_pub = {self.pubkeys_for_r1r[r1r]["key_s_pub"] for r1r in self.round1_responders}
       assert(len(set(all_c_pub).union(set(all_s_pub))) == 2*len(self.round1_responders))
       assert(len(self.round1_responders) >= THRESHOLD_CLIENTS, f"Only got {len(self.round1_responders)} responders, needed {THRESHOLD_CLIENTS} for security, aborting")


       # Generate random value
       prg_seed = get_random_bytes(PRG_SEED_SIZE) # b_u in Bhowmick et al. 2017
       self.prg_seed = prg_seed


       # Shamir sharings of prg_seed and s_sec
       prg_seed_shares = Shamir.split(k=THRESHOLD_CLIENTS,
                                n=len(self.round1_responders),
                                secret=prg_seed)
      
       # Shamir shares formatted as ((1, 0xdeadbeef), (2, 0xdeadbeef), ...)
       s_sec_shares_1 = Shamir.split(k=THRESHOLD_CLIENTS,
                             n=len(self.round1_responders),
                             secret=privkey_to_raw_bytes(self.key_s_sec)[:16])
       s_sec_shares_2 = Shamir.split(k=THRESHOLD_CLIENTS,
                             n=len(self.round1_responders),
                             secret=privkey_to_raw_bytes(self.key_s_sec)[16:])
       self.prg_seed_shares = prg_seed_shares
       self.s_sec_shares = (s_sec_shares_1, s_sec_shares_2)


       # Key agreement and build message to other users
       ciphertexts_for_other_r1r_r2 = {}
       for (r1r, i) in zip(self.round1_responders, range(len(self.round1_responders))):
           if r1r == self.client_id:
               continue
           else:
               # Derive and store shared key
               derived_key = derive_shared_key(self.client_id, r1r, self.key_c_sec,
                                   b64_to_pubkey(self.pubkeys_for_r1r[r1r]["key_c_pub"]))
               self.symmkeys_for_other_r1r[r1r] = derived_key
      
               # Build messages for other users
              
               message_for_other_r1r_r2 = {
                   "s_sec_share_xs": (s_sec_shares_1[i][0], s_sec_shares_2[i][0]),
                   "s_sec_share_ys": (bencode(s_sec_shares_1[i][1]),
                       bencode(s_sec_shares_2[i][1])),
                   "prg_seed_share_x": prg_seed_shares[i][0],
                   "prg_seed_share_y": bencode(prg_seed_shares[i][1])
               }
               print(f"message from {self.client_id} to {r1r}: {message_for_other_r1r_r2}", flush=True)
              
               associated_data = ids_to_associated_data(self.client_id, r1r)


               ciphertexts_for_other_r1r_r2[r1r] = encrypt_with_derived_key(
                   derived_key,
                   jencode_to_bytes(message_for_other_r1r_r2),
                   associated_data
               )
               print(f"ct from {self.client_id} to {r1r}: {ciphertexts_for_other_r1r_r2[r1r]}", flush=True)


       print("jencoding: ", jencode_ciphertexts_for_other_r1r_r2(ciphertexts_for_other_r1r_r2), flush=True)
      
       r2_payload = {
           'client_id': self.client_id,
           'round': 2,
           'payload': jencode_ciphertexts_for_other_r1r_r2(ciphertexts_for_other_r1r_r2)
       }
       return r2_payload


   def masked_input_collection(self, ciphertexts_from_server: dict) -> dict:
       self.round2_responders = [int(r2r_str) for r2r_str in ciphertexts_from_server.keys()]
       self.round2_responders.append(self.client_id) # add self to responders for this round
       vec_len = len(self.x_u)


       # Step 1: Decrypt ciphertexts from other users and store their shares
       # (needed in Round 4 for unmasking)
       for r2r in self.round2_responders:
           if r2r == self.client_id:
               continue


           ct_data = ciphertexts_from_server.get(str(r2r), ciphertexts_from_server.get(r2r))
           nonce_b64, ciphertext_b64 = ct_data
           nonce, ciphertext = jdecode_ciphertexts(nonce_b64, ciphertext_b64)
           derived_key = self.symmkeys_for_other_r1r[r2r]
           associated_data = ids_to_associated_data(r2r, self.client_id)


           plaintext_bytes = decrypt_with_derived_key(
               derived_key,
               nonce,
               ciphertext,
               associated_data
           )
           msg = jdecode_from_bytes(plaintext_bytes)


           # Store s_sec shares (two halves)
           self.received_s_sec_shares[r2r] = (
               (msg["s_sec_share_xs"][0], bdecode(msg["s_sec_share_ys"][0])),
               (msg["s_sec_share_xs"][1], bdecode(msg["s_sec_share_ys"][1]))
           )
           # Store prg_seed share
           self.received_prg_seed_shares[r2r] = (
               msg["prg_seed_share_x"],
               bdecode(msg["prg_seed_share_y"])
           )


       # Step 2: Compute pairwise masks p_{u,v} for all v in U2 \ {u}
       for r2r in self.round2_responders:
           if r2r == self.client_id:
               continue
           other_s_pub = b64_to_pubkey(self.pubkeys_for_r1r[r2r]["key_s_pub"])
           PRG_block = make_prg(self.client_id, r2r, self.key_s_sec, other_s_pub, vec_len)
           prg_elements = prg_block_to_field_elements(PRG_block, vec_len)
           p_u_v = []


           for elem in prg_elements:
               if self.client_id > r2r:
                   p_u_v.append(elem)
               else:
                   p_u_v.append(field_negate(elem))


           self.p_u_v[r2r] = p_u_v


       # Step 3: Compute personal mask p_u = PRG(b_u)
       PRG_block = make_prg2(self.client_id, self.client_id, self.prg_seed, vec_len)
       self.p_u = prg_block_to_field_elements(PRG_block, vec_len)


       # Step 4: Compute masked input y_u = x_u + p_u + sum_{v in U2\{u}} p_{u,v} (mod R)
       y_u = []
       for j in range(vec_len):
           val = self.x_u[j] % R
           val = field_add(val, self.p_u[j])
           for v in self.round2_responders:
               if v != self.client_id:
                   val = field_add(val, self.p_u_v[v][j])
           y_u.append(val)


       r3_payload = {
           'client_id': self.client_id,
           'round': 3,
           'payload': y_u
       }
       return r3_payload
      
   def unmasking(self, users_from_server: dict) -> dict:
       pass




def main():
   parser = argparse.ArgumentParser()
   parser.add_argument('--id', type=int, required=True, help='Client id (1..i for testing)')
   parser.add_argument('--vec', type=str, required="1,2,3", help='Input vector as comma-separated integers, e.g. "1,2,3"')
   args = parser.parse_args()
   client_id = args.id


   x_u = [int(x) for x in args.vec.split(",")]
   print(f"Client {client_id} starting with input vector {x_u}", flush=True)


   # Setup: Initialize client
   client = SecureAggregationClient(client_id=client_id, x_u=x_u)


   # Round 1: Advertise Keys
   r1_payload = client.advertise_keys()
   testing_delay = (client_id == 1) if DEBUG_TESTING_DELAY else False # if we are delaying a client for testing, which one?
   round_delay = 1 # if we are delaying a client for testing, which round to delay
   r1_response = do_round(client_id, 1, r1_payload, SERVER_URL)
  
   # Abort if nonparticipant in Round 1
   if 'status' in r1_response and r1_response['status'] == 'nonparticipant':
       print(f"Client {client_id} is a nonparticipant, aborting.", flush=True)
       return


   # Round 2: Share Keys
   r2_payload = client.share_keys(r1_response)
   if DEBUG: print(f"Client {client_id} round 2 payload: {r2_payload}", flush=True)
   r2_response = do_round(client_id, 2, r2_payload, SERVER_URL)
   print(f"Client {client_id} round 2 response: {r2_response}", flush=True)


   #Round 3: Masked Input Collection
   r3_payload = client.masked_input_collection(r2_response)
   print(f"Client {client_id} round 3 payload: {r3_payload}", flush=True)
   r3_response = do_round(client_id, 3, r3_payload, SERVER_URL)
   print(f"Client {client_id} round 3 response: {r3_response}", flush=True)


   # Remaining rounds
   for round in range(4, ROUNDS+1):
       payload = {'client_id': client_id, 'round': round, 'payload': f'Hello from client {client_id} round {round}'}
       print(f"Client {client_id}: Sending round {round}...", flush=True)
       resp = requests.post(f"{SERVER_URL}/round/{round}", json=payload)
       print(f"Client {client_id} round {round} response: {resp.json()}", flush=True)
       time.sleep(0.2)


if __name__ == '__main__':
   main()



