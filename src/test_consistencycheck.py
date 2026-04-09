import json
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Assuming these exist in your project as per previous context
from _client_helper import b64_to_pubkey, pubkey_to_b64, pubkey_to_bytes

class TestConsistencyCheckPayload:
    def test_top_level_keys(self, base_client):
        # Mocking a valid r3_response to prevent exit
        r3 = {"u2_users": list(range(10))} 
        p = base_client().consistency_check(r3)
        assert set(p) == {"client_id", "round", "payload"}
        assert p["round"] == 4

    def test_payload_contains_signature(self, base_client):
        r3 = {"u2_users": list(range(10))}
        p = base_client().consistency_check(r3)["payload"]
        assert "signature" in p

    def test_dummy_signature_for_passive_client(self, base_client):
        r3 = {"u2_users": list(range(10))}
        p = base_client(isactive=False).consistency_check(r3)["payload"]
        assert p["signature"] == "dummy"

class TestConsistencyLogic:
    def test_aborts_on_insufficient_users(self, base_client):
        # Testing the sys.exit(1) logic
        # Note: THRESHOLD_CLIENTS must be defined in your client module
        r3 = {"u2_users": [1, 2]} # Assuming threshold > 2
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            base_client().consistency_check(r3)
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 1

    def test_u3_list_is_sorted_in_state(self, base_client):
        client = base_client()
        unsorted_users = [10, 2, 5, 1]
        client.consistency_check({"u2_users": unsorted_users})
        assert client.u3_users == [1, 2, 5, 10]

class TestActiveConsistencySigning:
    def test_signature_valid_for_active_client(self, active_client_context):
        client, sk = active_client_context
        u3_list = [1, 5, 10, 12, 15]
        
        p = client.consistency_check({"u2_users": u3_list})
        sig_hex = p["payload"]["signature"]
        
        # The message signed is json.dumps(sorted_list)
        expected_message = json.dumps(sorted(u3_list)).encode("utf-8")
        
        # Verify using the Ed25519 public key
        sk.public_key().verify(bytes.fromhex(sig_hex), expected_message)

    def test_signature_fails_on_tampered_list(self, active_client_context):
        client, sk = active_client_context
        u3_list = [1, 2, 3, 4, 5, 6]
        
        p = client.consistency_check({"u2_users": u3_list})
        sig_hex = p["payload"]["signature"]
        
        # Tamper with the list and try to verify
        tampered_message = json.dumps([1, 2, 3, 4, 5, 7]).encode("utf-8")
        
        with pytest.raises(Exception): # cryptography raises InvalidSignature
            sk.public_key().verify(bytes.fromhex(sig_hex), tampered_message)