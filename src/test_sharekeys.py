import pytest
import json
import base64
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from _client_helper import pubkey_to_b64, pubkey_to_bytes
from client import SecureAggregationClient

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
def mock_r1_response():
    """Generates a dictionary representing keys from 3 clients."""
    response = {}
    client_keys = {} # Store keys to verify signatures later
    
    for cid in [1, 2, 5]: # Client 5 is often our 'local' client
        c_priv = x25519.X25519PrivateKey.generate()
        s_priv = x25519.X25519PrivateKey.generate()
        c_pub = c_priv.public_key()
        s_pub = s_priv.public_key()
        
        response[str(cid)] = {
            "key_c_pub": pubkey_to_b64(c_pub),
            "key_s_pub": pubkey_to_b64(s_pub)
        }
    return response

class TestShareKeysInputs:
    def test_abort_on_none_response(self, base_client):
        client = base_client()
        with pytest.raises(SystemExit):
            client.share_keys(None)

    def test_responder_list_initialization(self, base_client, mock_r1_response):
        client = base_client(client_id=5)
        # We need to run advertise_keys first to initialize local keys
        client.advertise_keys() 
        
        client.share_keys(mock_r1_response)
        assert set(client.round1_responders) == {1, 2, 5}
        assert 1 in client.pubkeys_for_r1r

class TestShareKeysVerification:
    def test_fails_on_invalid_signature(self, active_client_context, mock_r1_response):
        client, _, _ = active_client_context
        client.advertise_keys()
        
        # Add a signature field to one of the peer's data, but make it garbage
        mock_r1_response["1"]["signature"] = "deadbeef" * 8
        
        with pytest.raises(SystemExit):
            client.share_keys(mock_r1_response)

    def test_passes_with_valid_signatures(self, active_client_context):
        client, sk, sk1 = active_client_context
        client.advertise_keys()
        
        # Setup a response where client 1 has a valid signature
        c_pub = x25519.X25519PublicKey.from_public_bytes(b"\x01"*32)
        s_pub = x25519.X25519PublicKey.from_public_bytes(b"\x02"*32)
        msg = pubkey_to_bytes(c_pub) + pubkey_to_bytes(s_pub)
        sig = sk1.sign(msg).hex()
        
        valid_response = {
            "1": {
                "key_c_pub": pubkey_to_b64(c_pub),
                "key_s_pub": pubkey_to_b64(s_pub),
                "signature": sig
            },
            "5": { # Local client
                "key_c_pub": pubkey_to_b64(client.key_c_pub),
                "key_s_pub": pubkey_to_b64(client.key_s_pub),
                "signature": "doesn't matter for self"
            }
        }
        
        # This should not raise SystemExit
        client.share_keys(valid_response)

class TestSecretSharing:
    def test_uniqueness_constraint(self, base_client, mock_r1_response):
        client = base_client(client_id=5)
        client.advertise_keys()
        
        # Force a duplicate key to trigger the assert
        dup_key = mock_r1_response["1"]["key_c_pub"]
        mock_r1_response["2"]["key_c_pub"] = dup_key
        
        with pytest.raises(AssertionError):
            client.share_keys(mock_r1_response)

    def test_prg_seed_generation(self, base_client, mock_r1_response):
        client = base_client(client_id=5)
        client.advertise_keys()
        
        client.share_keys(mock_r1_response)
        assert hasattr(client, 'prg_seed')
        assert len(client.prg_seed) > 0

