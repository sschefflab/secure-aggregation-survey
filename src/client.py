#!/usr/bin/env python3
import base64
import requests
import argparse
import time
import json
import sys
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from config import (
    ROUNDS,
    THRESHOLD_CLIENTS,
    PRG_SEED_SIZE,
    DEBUG,
    DEBUG_TESTING_DELAY,
    FIELD_ELEMENT_SIZE,
    R,
)
from _client_helper import (
    bencode,
    bdecode,
    field_add,
    field_negate,
    jencode_to_bytes,
    jdecode_from_bytes,
    jencode_ciphertexts_for_other_r1r_r2,
    jdecode_ciphertexts,
    pubkey_to_b64,
    b64_to_pubkey,
    privkey_to_raw_bytes,
    do_round,
)
from _client_helper import (
    derive_shared_key,
    encrypt_with_derived_key,
    decrypt_with_derived_key,
    ids_to_associated_data,
    make_prg,
    make_prg2,
    prg_block_to_field_elements,
    field_negate,
    field_add,
)
from _client_helper import pubkey_to_bytes

SERVER_URL = "http://127.0.0.1:5000"


class SecureAggregationClient:
    def __init__(
        self,
        client_id: int,
        x_u: list[int],
        isactive: bool = False,
        signingkeyfile: str = None,
        verificationkeysfile: str = None,
    ):
        self.client_id = client_id
        self.x_u = x_u
        self.isactive = isactive
        self.key_c_pub = None
        self.key_c_sec = None
        self.key_s_pub = None
        self.key_s_sec = None
        self.round1_responders = list()  # is a list because we need consistent indexing
        self.pubkeys_for_r1r = {}
        self.symmkeys_for_other_r1r = {}
        self.s_sec_shares = None
        self.prg_seed = None
        self.prg_seed_shares = None
        self.p_u_v = {}
        self.p_u = None
        self.round2_responders = list()
        # Shares received from other users (decrypted in Round 3, used in Round 4)
        self.received_s_sec_shares = {}  # {sender_id: ((x1, y1), (x2, y2))}
        self.received_prg_seed_shares = {}  # {sender_id: (x, y)}
        self.key_d_pub = None
        self.key_d_sec = None
        # get signing and verfiication keys for active adversary
        if self.isactive:
            if signingkeyfile is not None and verificationkeysfile is not None:
                with open(signingkeyfile, "rb") as f:
                    self.signingkey = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
                self.verificationkeys = {}
                # verfication keys: {"id": hex_public_key}
                # Simply load using json.load
                with open(verificationkeysfile, "rb") as f:
                    verification_keys = json.load(f)
                    for client_id, pubkey_hex in verification_keys.items():
                        self.verificationkeys[int(client_id)] = (
                            ed25519.Ed25519PublicKey.from_public_bytes(
                                bytes.fromhex(pubkey_hex)
                            )
                        )

    def advertise_keys(self) -> dict:
        self.key_c_sec = X25519PrivateKey.generate()
        self.key_c_pub = self.key_c_sec.public_key()

        self.key_s_sec = X25519PrivateKey.generate()
        self.key_s_pub = self.key_s_sec.public_key()

        payload = {
            "client_id": self.client_id,
            "round": 1,
            "payload": {
                "key_c_pub": pubkey_to_b64(self.key_c_pub),
                "key_s_pub": pubkey_to_b64(self.key_s_pub),
            },
        }
        # Generate a signature sigma_u = SIG.sign(d_u_sk, c_u_pk||s_u_pk)
        if self.isactive:
            message = pubkey_to_bytes(self.key_c_pub) + pubkey_to_bytes(self.key_s_pub)
            signature = self.signingkey.sign(message)
            payload["payload"]["signature"] = signature.hex()

        return payload

    def share_keys(self, r1_response: dict) -> dict:
        if r1_response is None:
            print(
                f"Client {self.client_id} did not receive any response from server for round 1, aborting share keys.",
                flush=True,
            )
            sys.exit(1)

        # Set clients that responded in r1 and their keys
        self.round1_responders = [int(r1r_str) for r1r_str in r1_response.keys()]
        self.pubkeys_for_r1r = {
            int(r1r_str): r1_response[r1r_str] for r1r_str in r1_response.keys()
        }  # dict with int keys instead of str

        # verify signatures of other users' keys
        if self.isactive:
            for r1r in self.round1_responders:
                if r1r == self.client_id:
                    continue
                r1r_data = self.pubkeys_for_r1r[r1r]
                r1r_c_pub = b64_to_pubkey(r1r_data["key_c_pub"])
                r1r_s_pub = b64_to_pubkey(r1r_data["key_s_pub"])
                r1r_signature = bytes.fromhex(r1r_data["signature"])
                message = pubkey_to_bytes(r1r_c_pub) + pubkey_to_bytes(r1r_s_pub)
                try:
                    self.verificationkeys[r1r].verify(r1r_signature, message)
                except Exception as e:
                    print(
                        f"Client {self.client_id} failed to verify signature of client {r1r} in round 1, aborting. Error: {e}",
                        flush=True,
                    )
                    sys.exit(1)

        # Verify uniqueness of keys
        all_c_pub = {
            self.pubkeys_for_r1r[r1r]["key_c_pub"] for r1r in self.round1_responders
        }
        all_s_pub = {
            self.pubkeys_for_r1r[r1r]["key_s_pub"] for r1r in self.round1_responders
        }
        assert len(set(all_c_pub).union(set(all_s_pub))) == 2 * len(
            self.round1_responders
        )
        # assert(len(self.round1_responders) >= THRESHOLD_CLIENTS, f"Only got {len(self.round1_responders)} responders, needed {THRESHOLD_CLIENTS} for security, aborting")

        # Generate random value
        prg_seed = get_random_bytes(PRG_SEED_SIZE)  # b_u in Bhowmick et al. 2017
        self.prg_seed = prg_seed

        # Shamir sharings of prg_seed and s_sec
        prg_seed_shares = Shamir.split(
            k=THRESHOLD_CLIENTS, n=len(self.round1_responders), secret=prg_seed
        )

        # Shamir shares formatted as ((1, 0xdeadbeef), (2, 0xdeadbeef), ...)
        s_sec_shares_1 = Shamir.split(
            k=THRESHOLD_CLIENTS,
            n=len(self.round1_responders),
            secret=privkey_to_raw_bytes(self.key_s_sec)[:16],
        )
        s_sec_shares_2 = Shamir.split(
            k=THRESHOLD_CLIENTS,
            n=len(self.round1_responders),
            secret=privkey_to_raw_bytes(self.key_s_sec)[16:],
        )
        self.prg_seed_shares = prg_seed_shares
        self.s_sec_shares = (s_sec_shares_1, s_sec_shares_2)

        # Key agreement and build message to other users
        ciphertexts_for_other_r1r_r2 = {}
        for r1r, i in zip(self.round1_responders, range(len(self.round1_responders))):
            if r1r == self.client_id:
                continue
            else:
                # Derive and store shared key
                derived_key = derive_shared_key(
                    self.client_id,
                    r1r,
                    self.key_c_sec,
                    b64_to_pubkey(self.pubkeys_for_r1r[r1r]["key_c_pub"]),
                )
                self.symmkeys_for_other_r1r[r1r] = derived_key

                # Build messages for other users

                message_for_other_r1r_r2 = {
                    "s_sec_share_xs": (s_sec_shares_1[i][0], s_sec_shares_2[i][0]),
                    "s_sec_share_ys": (
                        bencode(s_sec_shares_1[i][1]),
                        bencode(s_sec_shares_2[i][1]),
                    ),
                    "prg_seed_share_x": prg_seed_shares[i][0],
                    "prg_seed_share_y": bencode(prg_seed_shares[i][1]),
                }
                print(
                    f"message from {self.client_id} to {r1r}: {message_for_other_r1r_r2}",
                    flush=True,
                )

                associated_data = ids_to_associated_data(self.client_id, r1r)

                ciphertexts_for_other_r1r_r2[r1r] = encrypt_with_derived_key(
                    derived_key,
                    jencode_to_bytes(message_for_other_r1r_r2),
                    associated_data,
                )
                print(
                    f"ct from {self.client_id} to {r1r}: {ciphertexts_for_other_r1r_r2[r1r]}",
                    flush=True,
                )

        print(
            "jencoding: ",
            jencode_ciphertexts_for_other_r1r_r2(ciphertexts_for_other_r1r_r2),
            flush=True,
        )

        r2_payload = {
            "client_id": self.client_id,
            "round": 2,
            "payload": jencode_ciphertexts_for_other_r1r_r2(
                ciphertexts_for_other_r1r_r2
            ),
        }
        return r2_payload

    def masked_input_collection(self, ciphertexts_from_server: dict) -> dict:
        if ciphertexts_from_server is None:
            print(
                f"Client {self.client_id} did not receive any ciphertexts from server for round 3, aborting masked input collection.",
                flush=True,
            )
            sys.exit(1)

        self.round2_responders = [
            int(r2r_str) for r2r_str in ciphertexts_from_server.keys()
        ]
        self.round2_responders.append(
            self.client_id
        )  # add self to responders for this round
        vec_len = len(self.x_u)

        # Step 1: Decrypt ciphertexts from other users and store their shares
        # (needed in Round 4 for unmasking)
        for r2r in self.round2_responders:
            if r2r == self.client_id:
                continue

            ct_data = ciphertexts_from_server.get(
                str(r2r), ciphertexts_from_server.get(r2r)
            )
            nonce_b64, ciphertext_b64 = ct_data
            nonce, ciphertext = jdecode_ciphertexts(nonce_b64, ciphertext_b64)
            derived_key = self.symmkeys_for_other_r1r[r2r]
            associated_data = ids_to_associated_data(r2r, self.client_id)

            plaintext_bytes = decrypt_with_derived_key(
                derived_key, nonce, ciphertext, associated_data
            )
            msg = jdecode_from_bytes(plaintext_bytes)

            # Store s_sec shares (two halves)
            self.received_s_sec_shares[r2r] = (
                (msg["s_sec_share_xs"][0], bdecode(msg["s_sec_share_ys"][0])),
                (msg["s_sec_share_xs"][1], bdecode(msg["s_sec_share_ys"][1])),
            )
            # Store prg_seed share
            self.received_prg_seed_shares[r2r] = (
                msg["prg_seed_share_x"],
                bdecode(msg["prg_seed_share_y"]),
            )

        # Step 2: Compute pairwise masks p_{u,v} for all v in U2 \ {u}
        for r2r in self.round2_responders:
            if r2r == self.client_id:
                continue
            other_s_pub = b64_to_pubkey(self.pubkeys_for_r1r[r2r]["key_s_pub"])
            PRG_block = make_prg(
                self.client_id, r2r, self.key_s_sec, other_s_pub, vec_len
            )
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

        r3_payload = {"client_id": self.client_id, "round": 3, "payload": y_u}
        return r3_payload

    def consistency_check(self, r3_response: dict) -> dict:
        u3_list = r3_response.get("u2_users", [])
        if not u3_list or len(u3_list) < THRESHOLD_CLIENTS:
            print(f"Consistency check: insufficient participants, aborting", flush=True)
            sys.exit(1)

        self.u3_users = sorted(u3_list)
        message_to_sign = json.dumps(self.u3_users).encode("utf-8")
        payload = {
            "client_id": self.client_id,
            "round": 4,
            "payload":{}
        }
        if self.isactive:
            payload["payload"]["signature"] = self.signingkey.sign(message_to_sign).hex()
        else:
            payload["payload"]["signature"] = "dummy"
        return payload

    def unmasking(self, r4_response: dict) -> dict:
        users_from_server = r4_response.get("users", None)
        if users_from_server is None:
            print(
                f"Client {self.client_id} did not receive any users from server for round 4, aborting unmasking.",
                flush=True,
            )
            sys.exit(1)

        round4_responders = [int(r4r_str) for r4r_str in users_from_server.keys()]

        if len(round4_responders) < THRESHOLD_CLIENTS:
            print(
                f"Secutity Alert: Only {len(round4_responders)} users survived, aborting.",
                flush=True,
            )
            sys.exit(1)

        # active adversary check: verify all signatures of the u3 list from round 3
        if self.isactive:
            u3_list_from_server = r4_response.get("u2_users", [])
            message_to_verify = json.dumps(u3_list_from_server).encode("utf-8")
            for other_id, sig in r4_response["u2_signatures"].items():
                other_id_int = int(other_id)
                if other_id_int == self.client_id:
                    continue
                try:
                    self.verificationkeys[other_id_int].verify(
                        bytes.fromhex(sig), message_to_verify
                    )
                except Exception as e:
                    print(
                        f"Client {self.client_id} failed to verify signature of client {other_id} in round 4, aborting. Error: {e}",
                        flush=True,
                    )
                    sys.exit(1)

        # Determine who dropped (in U2 but not in U3)
        dropped = set(self.round2_responders) - set(self.u3_users)
        survived = set(self.u3_users)

        shares_to_send = {}
        for v in dropped:
            if v in self.received_s_sec_shares:
                share1, share2 = self.received_s_sec_shares[v]
                shares_to_send[str(v)] = {
                    "type": "dropped",
                    "s_sec_share": [
                        [share1[0], bencode(share1[1])],
                        [share2[0], bencode(share2[1])],
                    ],
                }

        for v in survived:
            if v == self.client_id:
                continue
            if v in self.received_prg_seed_shares:
                share = self.received_prg_seed_shares[v]
                shares_to_send[str(v)] = {
                    "type": "survived",
                    "prg_seed_share": [share[0], bencode(share[1])],
                }

        r5_payload = {
            "client_id": self.client_id,
            "round": 5,
            "payload": shares_to_send,
        }
        return r5_payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--id", type=int, required=True, help="Client id (1..i for testing)"
    )
    parser.add_argument(
        "--vec",
        type=str,
        default="1,2,3",
        help='Input vector as comma-separated integers, e.g. "1,2,3"',
    )
    # each user rrecieve their signing key from the trusted third party
    parser.add_argument(
        "--signingkey",
        type=str,
        help="Path to file containing clients signing key for active adversary",
    )
    # each user recieves the verification keys d_u_pk bound to each user iednitity v
    parser.add_argument(
        "--verificationkeys",
        type=str,
        help="Path to file containing dict of verification keys for all users for active adversary",
    )

    args = parser.parse_args()
    client_id = args.id

    x_u = [int(x) for x in args.vec.split(",")]
    print(f"Client {client_id} starting with input vector {x_u}", flush=True)

    # Setup: Initialize client
    client = SecureAggregationClient(
        client_id=client_id,
        x_u=x_u,
        isactive=True,
        signingkeyfile=args.signingkey,
        verificationkeysfile=args.verificationkeys,
    )

    r1_response = do_round(client_id, 1, client.advertise_keys(), SERVER_URL)
    r2_response = do_round(client_id, 2, client.share_keys(r1_response), SERVER_URL)
    r3_response = do_round(
        client_id, 3, client.masked_input_collection(r2_response), SERVER_URL
    )
    r4_response = do_round(
        client_id, 4, client.consistency_check(r3_response), SERVER_URL
    )
    r5_response = do_round(client_id, 5, client.unmasking(r4_response), SERVER_URL)
    print(f"Aggregate: {r5_response.get('final_aggregate', None)}", flush=True)


if __name__ == "__main__":
    main()
