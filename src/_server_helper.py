#!/usr/bin/env python3
from flask import jsonify
from _client_helper import b64_to_pubkey, bdecode, field_add, field_negate, make_prg, make_prg2, prg_block_to_field_elements
from config import ROUNDS, DEBUG, MAX_CLIENTS, THRESHOLD_CLIENTS
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def extract_round_client_id_payload(data: dict, expected_round: int) -> tuple[int, int, dict]:
   # Extract round number from JSON body
   round = data.get('round')
   # Handle errors
   if round is None:
       raise ValueError('Error: Missing "round" field in JSON body')
   round = int(round)
   assert round == expected_round, f"Round number {expected_round} from POST does not match JSON body round number {round}"
   if not (1 <= round <= ROUNDS):
       raise ValueError(f"Error: Invalid round {round}; must be 1..{ROUNDS}")


   # Extract client_id from JSON body
   client_id = data.get('client_id')
   # TODO V2: HANDLE AUTHENTICATION! CURRENTLY WE DO NOT CHECK TO ENSURE CLIENT NOT LYING ABOUT ID.
   # Handle errors
   if client_id is None:
       raise ValueError('Error: Missing "client_id" field in JSON body')
   client_id = int(client_id)
   if not (1 <= client_id <= MAX_CLIENTS):
       raise ValueError(f"Error: Invalid client_id {client_id}; must be 1..{MAX_CLIENTS}")
  
   # Extract payload from JSON body
   payload = data.get('payload')
  
   return (round, client_id, payload)




def build_keyset_response(received_data: dict[int, dict[int, dict]], round1_responders: set[int]) -> dict[int, dict]:
   # received_data format: {round: {client_id: {payload}}}
   round1_data = received_data[1]
   return {client_id: round1_data[client_id] for client_id in round1_responders}


def build_sharekeys_response(client_id: int, received_data: dict[int, dict[int, dict]], round2_responders: set[int]) -> dict[int, dict]:
   # received_data format: {round: {client_id: {payload}}}
   # Received from client 3 in round 2: {'1': ['jNrWa3PZPHDvX391', 'xxx'], '2': ['kDUON98rzqdA98+n', 'xxx']}
   # TODO: CHANGE RECEIVED DATA TO ONLY INPUTTING THIS ROUND'S DATA
   round2_data = received_data[2]
   to_ret = {}
   for other_id in round2_responders:
       if other_id == client_id:
           continue
       if other_id not in round2_data or str(client_id) not in round2_data[other_id]:
           raise ValueError(f"Error: build_sharekeys_response called for client {client_id}, but no round 2 data from other client {other_id} for this client")
       to_ret[other_id] = round2_data[other_id][str(client_id)] # add received nonce and ciphertext from other_id for client_id to client_id's dictionary
   return to_ret


def build_masked_input_response(client_id: int, received_data: dict[int, dict[int, dict]], round3_responders: set[int]) -> dict[int, dict]:
   return {str(uid): {} for uid in round3_responders}


def compute_final_aggregate(received_data, round2_responders, round3_responders, round4_data, vec_len):
   """
   Compute the final aggregate: z = sum(y_u) - sum(p_u) - sum(p_{s,d})
   where s are surviving users and d are dropped users.
   """
   survived = set(round3_responders)
   dropped = set(round2_responders) - survived


   # Step 1: Sum all y_u for u in U3
   z = [0] * vec_len
   for u in round3_responders:
       y_u = received_data[3][u]
       for j in range(vec_len):
           z[j] = field_add(z[j], y_u[j])


   # Step 2: For surviving users, reconstruct b_u and subtract personal masks
   for u in survived:
       prg_seed_shares = []
       for reporter_id, reporter_shares in round4_data.items():
           target_key = str(u)
           if target_key in reporter_shares and reporter_shares[target_key]['type'] == 'survived':
               share_data = reporter_shares[target_key]['prg_seed_share']
               x = share_data[0]
               y = bdecode(share_data[1])
               prg_seed_shares.append((x, y))


       if len(prg_seed_shares) >= THRESHOLD_CLIENTS:
           b_u = Shamir.combine(prg_seed_shares[:THRESHOLD_CLIENTS])
           PRG_block = make_prg2(u, u, b_u, vec_len)
           p_u = prg_block_to_field_elements(PRG_block, vec_len)
           for j in range(vec_len):
               z[j] = field_add(z[j], field_negate(p_u[j]))


   # Step 3: For dropped users, reconstruct s_d^SK and subtract pairwise masks
   for d in dropped:
       s_sec_shares_1 = []
       s_sec_shares_2 = []
       for reporter_id, reporter_shares in round4_data.items():
           target_key = str(d)
           if target_key in reporter_shares and reporter_shares[target_key]['type'] == 'dropped':
               share_data = reporter_shares[target_key]['s_sec_share']
               s_sec_shares_1.append((share_data[0][0], bdecode(share_data[0][1])))
               s_sec_shares_2.append((share_data[1][0], bdecode(share_data[1][1])))


       if len(s_sec_shares_1) >= THRESHOLD_CLIENTS:
           s_d_sk_half1 = Shamir.combine(s_sec_shares_1[:THRESHOLD_CLIENTS])
           s_d_sk_half2 = Shamir.combine(s_sec_shares_2[:THRESHOLD_CLIENTS])
           s_d_sk = X25519PrivateKey.from_private_bytes(s_d_sk_half1 + s_d_sk_half2)


           # For each surviving user s, compute and subtract p_{s,d}
           for s in survived:
               s_s_pub = b64_to_pubkey(received_data[1][s]['key_s_pub'])
               PRG_block = make_prg(d, s, s_d_sk, s_s_pub, vec_len)
               prg_elements = prg_block_to_field_elements(PRG_block, vec_len)


               for j in range(vec_len):
                   # p_{s,d}: what surviving user s added for dropped user d
                   if s > d:
                       p_s_d_j = prg_elements[j]
                   else:
                       p_s_d_j = field_negate(prg_elements[j])
                   z[j] = field_add(z[j], field_negate(p_s_d_j))


   return z
                  


def response_if_not_responder(client_id: int, round_failed_to_respond: int) -> dict:
   return {'status': 'nonparticipant', 'message': f'Client {client_id} responded too late to participate in Round {round_failed_to_respond}.'}

