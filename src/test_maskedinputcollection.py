import pytest
import json
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Assuming these helpers exist in your project
from _client_helper import (
    pubkey_to_b64, 
    encrypt_with_derived_key, 
    ids_to_associated_data,
    jencode_to_bytes,
)
from client import SecureAggregationClient

# Constants for field math (Adjust based on your actual config)
R = 2**32 # Example field size

@pytest.fixture
def base_client():
    def _make_client(client_id=1, x_u=None, isactive=False, signing_key_file=None, verification_keys_file=None):
        if x_u is None:
            x_u = [0] * 10  # Default input vector of length 10
        return SecureAggregationClient(
            client_id=client_id,
            x_u=x_u or [0] * 10,
            isactive=isactive,
            signingkeyfile=signing_key_file,
            verificationkeysfile=verification_keys_file,
        )
    return _make_client

@pytest.fixture
def client_with_state(base_client):
    """
    Initializes a client and manually populates the internal state 
    required to enter Round 3.
    """
    client = base_client(client_id=10, x_u=[100, 200, 300])
    
    # 1. Setup own keys/seed
    client.key_s_sec = X25519PrivateKey.generate()
    client.key_s_pub = client.key_s_sec.public_key()
    client.prg_seed = b"a_very_secret_seed_32_bytes_long" 
    
    # 2. Setup knowledge of other clients (Round 1 leftovers)
    # We'll simulate one other client (ID: 20)
    other_sk = X25519PrivateKey.generate()
    client.pubkeys_for_r1r = {
        20: {"key_s_pub": pubkey_to_b64(other_sk.public_key())}
    }
    
    # 3. Setup symmetric keys for decryption (Round 2 leftovers)
    client.symmkeys_for_other_r1r = {
        20: b"symmetric_key_between_10_and_20_"
    }
    
    return client, other_sk

class TestMaskedInputStructure:
    def test_top_level_keys(self, client_with_state):
        client, _ = client_with_state
        # Empty dict or mock dict needed for input
        res = client.masked_input_collection({})
        assert set(res.keys()) == {"client_id", "round", "payload"}
        assert res["round"] == 3

    def test_payload_is_list(self, client_with_state):
        client, _ = client_with_state
        res = client.masked_input_collection({})
        assert isinstance(res["payload"], list)
        assert len(res["payload"]) == len(client.x_u)

class TestMaskingLogic:
    def test_decryption_and_storage(self, client_with_state):
        client, other_sk = client_with_state
        
        # Create a mock ciphertext from client 20 to client 10
        inner_msg = {
            "s_sec_share_xs": [1, 2],
            "s_sec_share_ys": [base64.b64encode(b"share1").decode(), base64.b64encode(b"share2").decode()],
            "prg_seed_share_x": 3,
            "prg_seed_share_y": base64.b64encode(b"share3").decode()
        }
        
        ad = ids_to_associated_data(20, client.client_id)
        nonce, ct = encrypt_with_derived_key(
            client.symmkeys_for_other_r1r[20],
            jencode_to_bytes(inner_msg),
            ad
        )
        
        server_input = {
            "20": [base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()]
        }
        
        client.masked_input_collection(server_input)
        
        # Verify shares were decrypted and stored correctly
        assert 20 in client.received_s_sec_shares
        assert client.received_s_sec_shares[20][0][1] == b"share1"

    def test_masking_math_consistency(self, client_with_state):
        """
        Verify that calling the function twice with same state results 
        in the same masked output (determinism).
        """
        client, _ = client_with_state
        res1 = client.masked_input_collection({})["payload"]
        
        # Reset ephemeral state that gets modified during the call if necessary
        # Note: In your provided code, p_u_v and p_u are overwritten, so it's fine.
        res2 = client.masked_input_collection({})["payload"]
        
        assert res1 == res2

class TestEdgeCases:
    def test_null_server_input_aborts(self, client_with_state):
        client, _ = client_with_state
        with pytest.raises(SystemExit):
            client.masked_input_collection(None)

    def test_empty_responders(self, client_with_state):
        client, _ = client_with_state
        # Even with no other responders, it should still apply the personal mask (p_u)
        res = client.masked_input_collection({})
        # y_u = x_u + p_u
        assert len(res["payload"]) == 3