import pytest
import json
import sys
from client import SecureAggregationClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from unittest.mock import MagicMock

# Assuming these exist in your helper or are accessible
# from _client_helper import bencode 

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
def active_client_context(tmp_path, base_client):
    cid = 5
    sk = ed25519.Ed25519PrivateKey.generate()

    raw_sk = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    
    vk_hex = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    
    cid_1 = 1
    sk_1= ed25519.Ed25519PrivateKey.generate()

    raw_sk_1 = sk_1.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    
    vk_hex_1 = sk_1.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    
    sign_path = tmp_path / "sign.bin"
    verif_path = tmp_path / "verif.json"
    print(f"Signing key path: {sign_path}")
    print(f"Verification key path: {verif_path}")
    sign_path.write_bytes(raw_sk)
    verif_path.write_text(json.dumps({str(cid): vk_hex, str(cid_1): vk_hex_1})) 

    client = base_client(client_id=cid, isactive=True, signing_key_file=str(sign_path), verification_keys_file=str(verif_path))

    return client, sk, sk_1


@pytest.fixture
def client_with_state(active_client_context, monkeypatch):
    import client as client_mod
    # Set threshold low so tests don't exit
    monkeypatch.setattr(client_mod, "THRESHOLD_CLIENTS", 1)
    
    # Unpack all 3 values from the previous fixture
    client, sk, sk_1 = active_client_context
    
    client.round2_responders = [1, 2, 3, 5]
    client.u3_users = [2, 5]
    
    # Mock shares (ensure these match the IDs in round2/u3)
    client.received_s_sec_shares = {
        1: [(1, b"share1_a"), (2, b"share1_b")],
        3: [(1, b"share3_a"), (2, b"share3_b")]
    }
    client.received_prg_seed_shares = {
        2: (1, b"seed_share2")
    }
    
    # Ensure verification keys exist for active check
    client.verificationkeys = {
        2: MagicMock(),
        1: MagicMock()
    }
    return client
    
class TestUnmaskingPayloadStructure:
    def test_top_level_keys(self, client_with_state):
        r4_response = {
            "users": {"2": {}, "5": {}},
            "u2_users": [2, 5],
            "u2_signatures": {}
        }
        p = client_with_state.unmasking(r4_response)
        assert set(p) == {"client_id", "round", "payload"}
        assert p["round"] == 5

    def test_empty_users_aborts(self, client_with_state):
        with pytest.raises(SystemExit):
            client_with_state.unmasking({"users": None})

class TestUnmaskingLogic:
    def test_shares_categorization(self, client_with_state):
        """Verify dropped users get s_sec_shares and survivors get prg_seed_shares."""
        r4_response = {
            "users": {"2": {}, "5": {}}, # Survived list from server
            "u2_users": [2, 5],
            "u2_signatures": {}
        }
        
        # We need to ensure THRESHOLD_CLIENTS isn't hit. 
        # For testing, you might need to monkeypatch the constant:
        # import client as client_mod
        # client_mod.THRESHOLD_CLIENTS = 1

        p = client_with_state.unmasking(r4_response)["payload"]
        
        # User 1 and 3 were in round2 but not u3 -> dropped
        assert p["1"]["type"] == "dropped"
        assert "s_sec_share" in p["1"]
        
        # User 2 was in u3 -> survived
        assert p["2"]["type"] == "survived"
        assert "prg_seed_share" in p["2"]
        
        # Client should not send shares for themselves
        assert "5" not in p

class TestUnmaskingActiveSecurity:
    def test_signature_verification_called(self, client_with_state):
        client_with_state.isactive = True
        u2_users = [2, 5]
        # Create a dummy signature
        sig_hex = "00" * 64 
        
        r4_response = {
            "users": {"2": {}, "5": {}},
            "u2_users": u2_users,
            "u2_signatures": {"2": sig_hex}
        }
        
        client_with_state.unmasking(r4_response)
        
        # Check if verify was called on the public key of user 2
        client_with_state.verificationkeys[2].verify.assert_called_once()

    def test_invalid_signature_aborts(self, client_with_state):
        client_with_state.isactive = True
        # Setup mock to raise error
        client_with_state.verificationkeys[2].verify.side_effect = Exception("Invalid")
        
        r4_response = {
            "users": {"2": {}, "5": {}},
            "u2_users": [2, 5],
            "u2_signatures": {"2": "bad_sig"}
        }
        
        with pytest.raises(SystemExit):
            client_with_state.unmasking(r4_response)

class TestUnmaskingEdgeCases:
    def test_threshold_failure(self, client_with_state, monkeypatch):
        # Force threshold to be high
        import client
        monkeypatch.setattr(client, "THRESHOLD_CLIENTS", 100)
        
        r4_response = {"users": {"2": {}, "5": {}}}
        with pytest.raises(SystemExit):
            client_with_state.unmasking(r4_response)