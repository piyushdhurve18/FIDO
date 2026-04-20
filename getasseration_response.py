import util
import cbor2
import credBlob
import hashlib
import getasserationrequest
import os
import struct
##### Case 1
def getasseration(response):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"**** GetAssertion Response ****")
    util.printcolor(util.YELLOW,"""Test started: P-1

        Parse GetAssertion response, and check that:
            (a) response includes "signature" field, and it's of type BYTE STRING
            (b) response includes "authData" field, and it's of type BYTE STRING
            (c) response MUST not include "user", "credential" and "numberOfCredentials".""")
##### case 2

def getasseration1(response,rpid):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"**** GetAssertion Response****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Parse GetAssertion_Response.authData and:
            (a) Check that it's exactly 37 bytes long
            (b) Check that authData.rpIdHash matches the hash of the GetAssertion_Request.rpId
            (c) Check that AT flag in authData.flags bitmap is not set.""")
    
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    # (a) Check length is exactly 37 bytes
    if len(authdata) != 37:
        raise AssertionError(f"authData length is {len(authdata)} bytes, expected 37.")

    # (b) Check rpIdHash matches SHA-256(rpid)
    rpidhash = authdata[0:32]  # first 32 bytes
    expected_hash = hashlib.sha256(rpid.encode("utf-8")).digest()
    if rpidhash != expected_hash:
        raise AssertionError("rpIdHash in authData does not match SHA-256(rpid).")

    # (c) Check AT flag not set
    flags = authdata[32]  # byte at index 32
    AT_FLAG = 0x40  # Bit 6 (0x40) = Attested Credential Data present
    if flags & AT_FLAG:
        raise AssertionError("AT flag is set in authData.flags but it must be unset.")

    util.printcolor(util.GREEN, "✅ GetAssertion P-2 test passed.")
    return True

def multi_getasseration_response(pin,rpid,response):
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"**** GetAssertion Response****")
    util.printcolor(util.YELLOW,"""Test started: P-3

        Send three valid CTAP2 authenticatorGetAssertion(0x02) request, wait for the responses, and check that response2.counter is bigger than response1.counter, and response3.counter is bigger than response2.counter.""")
    clientDataHash = util.sha256(os.urandom(32) )
    response1=getasserationrequest.makeAssertion(pin,clientDataHash,rpid,credId)#1
    authdata=credBlob.extract_authdata_from_makecredential_response(response1)
    counter1 = extract_counter_from_authdata(authdata)
    util.ResetCardPower()
    util.ConnectJavaCard()
    clientDataHash = util.sha256(os.urandom(32) )
    response2=getasserationrequest.makeAssertion(pin,clientDataHash,rpid,credId)#2
    authdata=credBlob.extract_authdata_from_makecredential_response(response2)
    counter2 = extract_counter_from_authdata(authdata)
    util.ResetCardPower()
    util.ConnectJavaCard()
    clientDataHash = util.sha256(os.urandom(32) )
    response3=getasserationrequest.makeAssertion(pin,clientDataHash,rpid,credId)#3
    authdata=credBlob.extract_authdata_from_makecredential_response(response3)
    counter3 = extract_counter_from_authdata(authdata)


    if not (counter2 > counter1):
        raise AssertionError(f"Counter did not increase: counter1={counter1}, counter2={counter2}")
    if not (counter3 > counter2):
        raise AssertionError(f"Counter did not increase: counter2={counter2}, counter3={counter3}")

    util.printcolor(util.GREEN, f"✅ Counter progression OK: {counter1} → {counter2} → {counter3}")
    return True



import os
import struct
import cbor2
import util
import getasserationrequest
import credBlob
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

def extract_public_key_from_authdata(authdata_bytes):
    """
    Extract COSE public key from authData and return it as raw bytes (COSE-encoded)
    """
    offset = 0
    rpIdHash = authdata_bytes[offset:offset+32]
    offset += 32
    flags = authdata_bytes[offset]
    offset += 1
    signCount = int.from_bytes(authdata_bytes[offset:offset+4], "big")
    offset += 4

    # Check if attested credential data is present
    if not (flags & 0x40):
        raise ValueError("No attested credential data in authData")

    aaguid = authdata_bytes[offset:offset+16]
    offset += 16
    credIdLen = int.from_bytes(authdata_bytes[offset:offset+2], "big")
    offset += 2
    credentialId = authdata_bytes[offset:offset+credIdLen]
    offset += credIdLen

    # The rest is COSE public key (CBOR map)
    cose_key_bytes = authdata_bytes[offset:]
    return cose_key_bytes,credentialId

def getasseration_signature_verify(pin, rpid, response):
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    cosekey,credIds=extract_public_key_from_authdata(authdata)
    print("aloo",credIds)
    print("cosekey",cosekey)
    credId =getasserationrequest.authParasing(response)
    print("credid:",credId)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** GetAssertion Response ****")
    util.printcolor(util.YELLOW, """Test started: P-4

        Merge authData and clientDataHash, and using previously acquired publicKey
        verify signature from GetAssertion_Response.""")
    clientDataHash = util.sha256(os.urandom(32) )
    response=getasserationrequest.makeAssertion(pin,clientDataHash,rpid,credId)















import cbor2

def extract_public_key_from_authdata1(authdata_bytes):
    offset = 0

    # Skip RP ID hash (32), flags (1), counter (4)
    offset += 32 + 1 + 4

    # Skip AAGUID (16)
    offset += 16

    # Read Credential ID length (2 bytes, big-endian)
    cred_id_len = int.from_bytes(authdata_bytes[offset:offset+2], "big")
    offset += 2

    # Skip Credential ID itself
    offset += cred_id_len

    # Remaining is the CBOR-encoded COSE_Key
    cose_key = cbor2.loads(authdata_bytes[offset:])
    return cose_key
















def parse_getassertion_cbor(response):
    """Decode GetAssertion CBOR payload into dict"""
    if isinstance(response, bytes):
        if response[0] == 0x00:
            return cbor2.loads(response[1:])
        else:
            raise ValueError(f"Invalid CTAP2 status code: 0x{response[0]:02X}")
    elif isinstance(response, dict):
        return response
    else:
        raise TypeError("Unsupported GetAssertion response format")


def load_cose_public_key(cose_key_bytes):
    """
    Convert COSE_Key bytes (EC2) into cryptography's EllipticCurvePublicKey
    COSE EC2 key structure:
      1: key type (2=EC2)
      3: alg (-7=ES256)
     -1: crv (1=P-256)
     -2: x-coordinate (bytes)
     -3: y-coordinate (bytes)
    """
    cose_key = cbor2.loads(cose_key_bytes)
    x = int.from_bytes(cose_key[-2], "big")
    y = int.from_bytes(cose_key[-3], "big")
    curve = ec.SECP256R1()

    public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
    return public_numbers.public_key()


def extract_counter_from_authdata(authdata_bytes):
    """
    Extracts the 4-byte signature counter from raw authData bytes
    authData structure:
      0-31   : rpIdHash
      32     : flags
      33-36  : signature counter (big endian)
    """
    if not isinstance(authdata_bytes, (bytes, bytearray)):
        raise TypeError("authdata must be raw bytes")

    if len(authdata_bytes) < 37:
        raise ValueError(f"authData too short ({len(authdata_bytes)} bytes) to contain counter")

    counter_bytes = authdata_bytes[33:37]
    return struct.unpack(">I", counter_bytes)[0]