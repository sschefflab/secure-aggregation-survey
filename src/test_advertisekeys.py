import base64
import json
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ed25519

from _client_helper import b64_to_pubkey, pubkey_to_b64, pubkey_to_bytes
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
    
    sign_path = tmp_path / "sign.bin"
    verif_path = tmp_path / "verif.json"
    print(f"Signing key path: {sign_path}")
    print(f"Verification key path: {verif_path}")
    sign_path.write_bytes(raw_sk)
    verif_path.write_text(json.dumps({str(cid): vk_hex}))

    client = base_client(client_id=cid, isactive=True, signing_key_file=str(sign_path), verification_keys_file=str(verif_path))

    return client, sk

class TestPayloadStructure:
    def test_top_level_keys(self, base_client):
        p = base_client().advertise_keys()
        assert set(p) == {"client_id", "round", "payload"}

    @pytest.mark.parametrize("cid", [0, 7, 2**31 - 1])
    def test_client_id_handling(self, base_client, cid):
        p = base_client(client_id=cid).advertise_keys()
        assert p["client_id"] == cid

    def test_round_is_1(self, base_client):
        p = base_client().advertise_keys()
        assert p["round"] == 1

    def test_inner_payload_keys_passive(self, base_client):
        p = base_client().advertise_keys()["payload"]
        assert set(p) == {"key_c_pub", "key_s_pub"}

class TestKeyGeneration:
    def test_keys_are_valid_x25519(self, base_client):
        p = base_client().advertise_keys()["payload"]
        assert isinstance(b64_to_pubkey(p["key_c_pub"]), X25519PublicKey)
        assert isinstance(b64_to_pubkey(p["key_s_pub"]), X25519PublicKey)

    def test_keys_are_32(self, base_client):
        p = base_client().advertise_keys()["payload"]
        for k in ("key_c_pub", "key_s_pub"):
            assert len(base64.b64decode(p[k])) == 32

    def test_instance_state_set(self, base_client):
        client = base_client()
        client.advertise_keys()
        assert all(x is not None for x in [
            client.key_c_sec, client.key_c_pub,
            client.key_s_sec, client.key_s_pub
        ])

    def test_payload_matches_instance_state(self, base_client):
        client = base_client()
        p = client.advertise_keys()["payload"]
        assert p["key_c_pub"] == pubkey_to_b64(client.key_c_pub)
        assert p["key_s_pub"] == pubkey_to_b64(client.key_s_pub)

    def test_repeated_calls_produce_fresh_keys(self, base_client):
        client = base_client()
        p1 = client.advertise_keys()["payload"]
        p2 = client.advertise_keys()["payload"]
        assert p1["key_c_pub"] != p2["key_c_pub"]
        assert p1["key_s_pub"] != p2["key_s_pub"]

class TestActiveSigning:

    def test_signature_present(self, active_client_context):
        client, _ = active_client_context
        assert "signature" in client.advertise_keys()["payload"]

    def test_signature_valid(self, active_client_context):
        client, sk = active_client_context
        p = client.advertise_keys()
        inner = p["payload"]
        msg = (pubkey_to_bytes(b64_to_pubkey(inner["key_c_pub"])) + pubkey_to_bytes(b64_to_pubkey(inner["key_s_pub"])))

        sk.public_key().verify(bytes.fromhex(inner["signature"]), msg)

    def test_signatures_covers_both_keys(self, active_client_context):
        client, sk = active_client_context
        inner = client.advertise_keys()["payload"]
        sig = bytes.fromhex(inner["signature"])
        with pytest.raises(InvalidSignature):
            sk.public_key().verify(sig, b"\x00")

    def test_signature_changes_per_call(self, active_client_context):
        client, sk = active_client_context
        p1 = client.advertise_keys()
        p2 = client.advertise_keys()
        assert p1["payload"]["signature"] != p2["payload"]["signature"]

class TestingEdgeCases:
    def test_active_flag_without_key_files_raises_on_sign(self, base_client):
        client = base_client(isactive=True, signing_key_file=None, verification_keys_file=None)
        with pytest.raises(AttributeError):
            client.advertise_keys()
    
    def test_empty_x_u(self, base_client):
        p = base_client(x_u=[]).advertise_keys()
        assert p["round"] == 1
