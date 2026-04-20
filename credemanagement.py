import cbor2
import hashlib
import hmac
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES

class CredentialManagementProtocol2:
    def __init__(self, send_apdu_func):
        self.send_apdu = send_apdu_func

    def build_ctap2_apdu(self, cmd, payload):
        # Wraps CBOR payload in CTAP2 APDU format: CLA=0x80, INS=0x10
        return bytes([0x80, 0x10, 0x00, 0x00, len(payload)]) + payload

    def parse_cose_key(self, cose_key):
        # Extract X, Y coordinates from COSE key
        x = cose_key[-2]  # -2: x-coordinate
        y = cose_key[-3]  # -3: y-coordinate
        return int.from_bytes(x, 'big'), int.from_bytes(y, 'big')

    def generate_shared_secret(self, peer_cose_key):
        peer_x, peer_y = self.parse_cose_key(peer_cose_key)
        peer_point = ECC.EccPoint(peer_x, peer_y, curve='P-256')
        self.ecdh_private = ECC.generate(curve='P-256')
        shared_point = peer_point * self.ecdh_private.d
        x_bytes = int(shared_point.x).to_bytes(32, 'big')
        return hashlib.sha256(x_bytes).digest()

    def get_platform_cose_key(self):
        pub_point = self.ecdh_private.public_key().pointQ
        x = int(pub_point.x).to_bytes(32, 'big')
        y = int(pub_point.y).to_bytes(32, 'big')
        return {
            1: 2,      # kty: EC2
            3: -25,    # alg: ECDH-ES + HKDF-256
            -1: 1,     # crv: P-256
            -2: x,
            -3: y
        }

    def aes256_cbc_encrypt(self, key, data):
        pad_len = 16 - len(data) % 16
        padded = data + bytes([pad_len] * pad_len)
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))  # IV=all zeros
        return cipher.encrypt(padded)

    def sha256_pin_hash(self, pin):
        return hashlib.sha256(pin.encode()).digest()[:16]

    def hmac_sha256(self, key, message):
        return hmac.new(key, message, hashlib.sha256).digest()[:16]

    def call(self, pin: str):
        # Step 1: Get Key Agreement (Client PIN 0x06, subCommand=0x02)
        get_key_agreement_map = {1: 2, 2: 2}  # pinUvAuthProtocol=2, subCommand=2
        payload = cbor2.dumps(get_key_agreement_map)
        apdu = self.build_ctap2_apdu(0x06, payload)
        response = self.send_apdu(apdu)
        response_cbor = cbor2.loads(response)
        peer_key = response_cbor[1]

        # Step 2: Generate shared secret and our COSE public key
        shared_secret = self.generate_shared_secret(peer_key)
        platform_key = self.get_platform_cose_key()

        # Step 3: Generate PIN hash and encrypt it with shared secret
        pin_hash = self.sha256_pin_hash(pin)
        pin_hash_enc = self.aes256_cbc_encrypt(shared_secret, pin_hash)

        # Step 4: Get PIN Token (Client PIN 0x06, subCommand=0x05)
        get_pin_token_map = {
            1: 2,           # pinUvAuthProtocol = 2
            2: 5,           # subCommand = getPINToken
            3: platform_key,
            5: pin_hash_enc
        }
        payload = cbor2.dumps(get_pin_token_map)
        apdu = self.build_ctap2_apdu(0x06, payload)
        response = self.send_apdu(apdu)
        response_cbor = cbor2.loads(response)
        pin_token = response_cbor[2]

        # Step 5: Construct Credential Management request (0x0A)
        sub_command = 0x01  # getCredsMetadata
        cmd_byte = 0x0A
        auth_message = bytes([cmd_byte, sub_command])
        pin_uv_auth_param = self.hmac_sha256(pin_token, auth_message)

        credential_mgmt_map = {
            1: sub_command,     # subCommand = getCredsMetadata
            3: 2,               # pinUvAuthProtocol = 2
            4: pin_uv_auth_param
        }
        payload = cbor2.dumps(credential_mgmt_map)
        apdu = self.build_ctap2_apdu(cmd_byte, payload)
        response = self.send_apdu(apdu)
        result = cbor2.loads(response)

        print("✅ Credential Metadata Response:", result)
