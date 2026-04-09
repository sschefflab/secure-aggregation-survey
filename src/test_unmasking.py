import pytest
import json
import sys
from unittest.mock import MagicMock

# Assuming these exist in your helper or are accessible
# from _client_helper import bencode 

@pytest.fixture
def client_with_state(active_client_context):
    client, sk = active_client_context
    # Mock threshold and internal round data
    client.round2_responders = [1, 2, 3, 5] # 5 is self
    client.u3_users = [2, 5]               # 2 survived, 1 and 3 dropped
    
    # Mock received shares (ID: [index, share_bytes])
    client.received_s_sec_shares = {
        1: [(1, b"share1_a"), (2, b"share1_b")],
        3: [(1, b"share3_a"), (2, b"share3_b")]
    }
    client.received_prg_seed_shares = {
        2: (1, b"seed_share2")
    }
    
    # Mock verification keys for other users
    # In a real test, you'd populate this with Ed25519 public keys
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