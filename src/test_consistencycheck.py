import json
from client import SecureAggregationClient
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Assuming these exist in your project as per previous context
from _client_helper import b64_to_pubkey, pubkey_to_b64, pubkey_to_bytes

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
        # Correctly unpack the 3-tuple returned by the fixture
        client, sk, _ = active_client_context 
        
        # Ensure THRESHOLD_CLIENTS is small enough for this list
        u3_list = [1, 5, 10, 12, 15]
        
        p = client.consistency_check({"u2_users": u3_list})
        sig_hex = p["payload"]["signature"]
        
        expected_message = json.dumps(sorted(u3_list)).encode("utf-8")
        
        # This will now work because sk is correctly assigned
        sk.public_key().verify(bytes.fromhex(sig_hex), expected_message)

    def test_signature_fails_on_tampered_list(self, active_client_context):
        client, sk, _ = active_client_context
        u3_list = [1, 2, 3, 4, 5, 6]
        
        p = client.consistency_check({"u2_users": u3_list})
        sig_hex = p["payload"]["signature"]
        
        tampered_message = json.dumps([1, 2, 3, 4, 5, 7]).encode("utf-8")
        
        with pytest.raises(Exception): 
            sk.public_key().verify(bytes.fromhex(sig_hex), tampered_message)