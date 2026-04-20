####################
#   [Author]
#     REDPATH
#
#   [Intent]
#    Utils for all functions needed
#
#   [Install]
#     pip3 install smartcard
#     pip3 install cbor2
#     pip3 install python-secrets
#     pip3 install cryptography
################################ 
import textwrap, sys, json, base64
import cbor2, secrets
from smartcard.System import readers
from smartcard.ATR import ATR
from smartcard.util import toHexString
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib,os
import requests
import argparse, textwrap
import util
import logging

RED = "\033[1;31m"
REDWHITE = "\033[41m\033[97m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;43m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"
ORANGE="\033[38;5;214m"
ORANGEBLACK= "\033[30;48;5;214m"
NC = "\033[0m"

curlserver = False
connection = None
global maxAllowedCredCount

args = None
def parseCmdline():
    global args
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
           additional information:
             The Curl Test Server can be used instead of a real Java Card
             Use the --curl on for the Server
         '''))
    parser.add_argument('--curl', help="default is off", choices=["on", "off"], default="off")
    args = parser.parse_args()
    
class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')  # Convert bytes to base64 string
        return super().default(obj)

def pad_pin2(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    if len(pin) < 4:
        raise ValueError("PIN must be >= 4 characters")
    pin_padded = pin.encode().ljust(64, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
    if len(pin_padded) > 255:
        raise ValueError("PIN must be <= 255 bytes")
    return pin_padded



def pad_pin1(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN must be a string, got {type(pin)}")
    
    # Let the authenticator validate the length instead of raising here.
    pin_bytes = pin.encode()

    # Pad the PIN to 64 bytes with null (0x00)
    pin_padded = pin_bytes.ljust(64, b"\0")
    # Ensure total length is a multiple of 16 bytes
    pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)

    return pin_padded

def pad_pin(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    pin_padded = pin.encode().ljust(64, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
    
    return pin_padded

def pad_pin_with_expected_length(pin: str, length: int) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    pin_padded = pin.encode().ljust(length, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16))
    util.printcolor(util.YELLOW, f"{length} bytes new_pin_padded ==> : {pin_padded.hex()}")
    
    return pin_padded

def pad_pin_not_64bytes(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    pin_padded = pin.encode().ljust(65, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16))
    util.printcolor(util.BLUE, f"65 bytes new_pin_padded ==> : '{pin_padded.hex()}'")

    return pin_padded


def pad_pin_minimal(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    pin_bytes = pin.encode()
    # Pad only to 16 bytes for AES
    pad_len = 16 - (len(pin_bytes) % 16)
    pin_padded = pin_bytes + b"\0" * pad_len
    return pin_padded

def withoupadded(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    pin_bytes = pin.encode()

    return pin_bytes

def pintoken(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

def wrongpad_pin(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")

    # Step 1: Normal pad to 64 bytes
    pin_padded = pin.encode().ljust(64, b"\x00")

    # Step 2: Convert to mutable bytearray
    out = bytearray(pin_padded)

    # Step 3: Insert AB CD at position 16
    out[16:18] = bytes.fromhex("ABCD")
    #util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
    util.printcolor(util.YELLOW,f" pin_padded : {out.hex()}")
    
    return bytes(out)

import random
def random_int(length):
    return random.randint(10**(length - 1), 10**length - 1)

print(random_int(6))  # e.g. 483920





   

def pad_pin1(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    
    pin_bytes = pin.encode("utf-8")

    if len(pin_bytes) < 4:
        raise ValueError("PIN must be at least 4 bytes long")

    if len(pin_bytes) > 64:
        raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # pad to 64 bytes with 0x00




def bytes2int(value: bytes) -> int:
    """Parses an arbitrarily sized integer from a byte string.

    :param value: A byte string encoding a big endian unsigned integer.
    :return: The parsed int.
    """
    return int.from_bytes(value, "big")


    
def int2bytes(value: int, minlen: int = -1) -> bytes:
    """Encodes an int as a byte string.

    :param value: The integer value to encode.
    :param minlen: An optional minimum length for the resulting byte string.
    :return: The value encoded as a big endian byte string.
    """
    ba = []
    while value > 0xFF:
        ba.append(0xFF & value)
        value >>= 8
    ba.append(value)
    ba.extend([0] * (minlen - len(ba)))
    return bytes(reversed(ba))



def sha256(data: bytes) -> bytes:
    """Produces a SHA256 hash of the input.

    :param data: The input data to hash.
    :return: The resulting hash.
    """
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()
    
#######
#  Hash-based Message Authentication Code
#  The HMAC-SHA-256 combines SHA-256 with a secret key to produce a
#  hash that authenticates the data source and verifies its integrity.
#  HMAC-SHA-256 provides both data integrity and authentication because
#  it requires a secret key.
#
#  [example]
#    shared_secret = b'Sixteen byte key'  # Ensure this is in bytes
#    new_pin_enc = b'123456'  # Ensure this is in bytes
#    hmac_result = hmac_sha256(shared_secret, new_pin_enc)
###################
def hmac_sha256(shared_secret, message):
    # Create HMAC object with SHA-256
    hmac_obj = hmac.new(shared_secret, message, hashlib.sha256)
    # Return the HMAC digest
    return hmac_obj.digest()





def hmacs_sha256(shared_secret, message):
    if isinstance(shared_secret, str):
        shared_secret = bytes.fromhex(shared_secret)
    if isinstance(message, str):
        message = bytes.fromhex(message)
    return hmac.new(shared_secret, message, hashlib.sha256).digest()

def Hmacs_sha256(shared_secret, message):
    if isinstance(shared_secret, str):
        shared_secret = bytes.fromhex(shared_secret)
    if isinstance(message, str):
        message = bytes.fromhex(message)
    return hmac.new(shared_secret, message, hashlib.sha256).digest()

def kdfProtocolV1(self, z: bytes) -> bytes:
    IV = b"\x00" * 16
    return sha256(z)
    
#################
#  kdfProtocolV2
#
#################
def kdfProtocolV2(z):
    VERSION = 2
    HKDF_SALT = b"\x00" * 32
    HKDF_INFO_HMAC = b"CTAP2 HMAC key"
    HKDF_INFO_AES = b"CTAP2 AES key"
    be = default_backend()
    hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=HKDF_INFO_HMAC,
            backend=be,
        ).derive(z)
    aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=HKDF_INFO_AES,
            backend=be,
        ).derive(z)
    return hmac_key + aes_key  # 64 byte

##################
#   ProtcolV2 assumed
##################
def encapsulate(peer_cose_key):
    be = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pn = sk.public_key().public_numbers()
    key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

    x = bytes2int(peer_cose_key[-2])
    y = bytes2int(peer_cose_key[-3])
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
    shared_secret = kdfProtocolV2(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
    return key_agreement, shared_secret 


####worong keyagrreemt

def wrongencapsulate(peer_cose_key):
    be = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pn = sk.public_key().public_numbers()
    key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 3,
            -2: int2bytes(pn.x,32),
            -3: int2bytes(pn.y, 32),
           
             
        }

    x = bytes2int(peer_cose_key[-2])
    y = bytes2int(peer_cose_key[-3])
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
    shared_secret = kdfProtocolV2(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
    #here add key_agreement
    return key_agreement, shared_secret 

##########################
#  ProtcolV1 assumed
##########################
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def encapsulate_protocol1(peer_cose_key):
    be = default_backend()

    # Generate ephemeral key pair (private + public)
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pub = sk.public_key().public_numbers()

    # Build our public COSE_Key structure (as per spec)
    key_agreement = {
        1: 2,     # kty: EC2
        3: -25,   # alg: -25 (not actually used, per spec)
        -1: 1,    # crv: P-256
        -2: int2bytes(pub.x, 32),  # x-coordinate
        -3: int2bytes(pub.y, 32),  # y-coordinate
    }

    # Parse peer’s public key (x and y)
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(be)

    # Compute ECDH shared point
    shared_point = sk.exchange(ec.ECDH(), peer_pub)

    # Take only x-coordinate and hash it using SHA-256 as KDF
    shared_secret = hashlib.sha256(shared_point).digest()  # ✅ Protocol 1 KDF

    return key_agreement, shared_secret


##################
# [Fido Spec]
#  pinAuth:LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16).
#######################
def hmac_sha256_left_16(shared_secret, message):
    # Compute the HMAC-SHA-256
    hmac_result = hmac.new(shared_secret, message, hashlib.sha256).digest()
    # Take the leftmost 16 bytes
    return hmac_result[:16]

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes256_cbc_encrypt1(shared_secret, data):
    # FIDO2 Protocol 1 requires IV of all 0x00
    iv = b'\x00' * 16

    # FIDO2 spec: data must be multiple of 16 bytes, use zero-padding
    if len(data) % 16 != 0:
        padding_len = 16 - (len(data) % 16)
        data += b'\x00' * padding_len

    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext  # ✅ DO NOT prepend IV


##########
#   Set up AES cipher with a IV and prepend. When you prepend the IV (Initialization Vector)
#   and sometimes a salt to the encrypted result in AES-256-CBC, it's commonly known as IV
#   prepending (or "ciphertext with IV")
#   Data is a multiple of 16 bytes, as there is padding 0x00 in this setup.
#
#  [Fido Spec says]
# 
#
##########
def aes256_cbc_encrypt(shared_secret, data):
    # Calculate the number of padding bytes needed
    padding_needed = 16 - (len(data) % 16)
    # Only pad if data length is not already a multiple of 16

    if padding_needed != 16:
        data += b'\x00' * padding_needed

    iv = os.urandom(16)




# Spec says IV(0)  but we will not do that!!!!
#    iv = b'\x00' * 16  # 16-byte IV of all zeroes As per spec FIDO


    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt without padding (data should be a multiple of block size, 16 bytes for AES)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    # strCipher = util.toHex(ciphertext)
    # strIV = util.toHex(iv)
    # util.printcolor(util.YELLOW, f"ciphertext -> {strCipher}")
    # util.printcolor(util.YELLOW, f"IV -> {strIV} ")

    return iv + ciphertext

##########
def aes256_cbc_decrypt(shared_secret,iv, data):

    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext

#def printcolor(color, text):
    #sys.stdout.write(color + text + NC)
    #print()


def printcolor(color, text):
    if sys.stdout.isatty():  # Check if output is terminal
        # Show colored text only in terminal
        print(color + text + NC)
    else:
        # In log file, skip color codes
        print(text)

    logging.info(text.encode('ascii', errors='ignore').decode())

def printcolor1(color, text):
    sys.stdout.write(color + text + NC)
    logging.info(text)


def printstr(v):
    ascii_string = ''.join(chr(x) for x in v)
    printcolor(ORANGE,ascii_string)

def toHex(arr):
    hexstring = ''.join(format(x, '02X') for x in arr)
    return hexstring

def printhexstr(v):
    hex_string = ''.join(format(x, '02X') for x in v)
    # print(hex_string)
    return hex_string


def key_agreementnotmap(peer_cose_key):
    be = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pn = sk.public_key().public_numbers()
    key_agreement = [
        2,
        -25,
        1,
        int2bytes(pn.x, 32),
        int2bytes(pn.y, 32)
    ]
   
 
    x = bytes2int(peer_cose_key[-2])
    y = bytes2int(peer_cose_key[-3])
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
    shared_secret = kdfProtocolV2(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
    return key_agreement, shared_secret



def wrongkeysharesecret(peer_cose_key):
    be = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pn = sk.public_key().public_numbers()
    key_agreement = {
            1: 2,
            3: -7,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }
 
    x = bytes2int(peer_cose_key[-2])
    y = bytes2int(peer_cose_key[-3])
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
    shared_secret = kdfProtocolV2(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
    #wrong sharesecrt
    bad_shared_secret = bytearray(shared_secret)
    bad_shared_secret[0] ^= 0xFF
    bad_shared_secret = bytes(bad_shared_secret)
   
    return key_agreement, shared_secret
 
def wrongkeyagreement(peer_cose_key):
    be = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), be)
    pn = sk.public_key().public_numbers()
    key_agreement = {
            1: 2,
            3: -7,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }
 
    x = bytes2int(peer_cose_key[-2])
    y = bytes2int(peer_cose_key[-3])
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
    shared_secret = kdfProtocolV2(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
   
    return key_agreement, shared_secret
 
 
##########
# Go to Curl test Simulator
###########
def curlServerGet(hexstring, silent=False):
   url = "http://localhost:8080/"+hexstring
   response = requests.get(url)
   if not silent:
       print(response.text)
   parsed_string =    response.text.split('#')[-1]
   status = parsed_string[-4:]
   print(f"status parsed: {status}")
   number = int(status, 16)
   result = parsed_string[:-4]
   return result, number

def split_into_real_apdus(apdu_str):
    apdus = []
    i = 0

    while i + 10 <= len(apdu_str):
        cla = apdu_str[i:i+2]
        lc  = int(apdu_str[i+8:i+10], 16)

        apdu_len = 10 + (lc * 2)

        # Last APDU has Le (00)
        if cla == "80":
            apdu_len += 2

        apdus.append(apdu_str[i:i+apdu_len])
        i += apdu_len

    return apdus

# def split_into_real_apdus_le(apdu_str):
#     apdus = []
#     i = 0
#     total_len = len(apdu_str)

#     while i + 8 <= total_len:
#         start = i

#         # Minimum header
#         cla = apdu_str[i:i+2]
#         ins = apdu_str[i+2:i+4]
#         p1  = apdu_str[i+4:i+6]
#         p2  = apdu_str[i+6:i+8]

#         i += 8

#         # If no more bytes → Case 1
#         if i == total_len:
#             apdus.append(apdu_str[start:i])
#             break

#         remaining = total_len - i
#         # Read next byte
#         next_byte = int(apdu_str[i:i+2], 16)

#         # Extended length APDU
#         if next_byte == 0x00:
#             # Need at least 4 more hex chars for LcHi LcLo
#             if i + 6 > total_len:
#                 raise ValueError("Invalid extended APDU length")

#             lc = int(apdu_str[i+2:i+6], 16)
#             i += 6
#         else:
#             lc = next_byte
#             i += 2

#         data_hex_len = lc * 2


#         # Ensure enough bytes for data
#         if i + data_hex_len > total_len:
#             raise ValueError("Invalid APDU length (data overflow)")

#         i += data_hex_len

#         # Check if Le exists
#         if i + 2 <= total_len:
#             # If exactly 2 bytes left → Case 4
#             if (total_len - i) == 2:
#                 i += 2

#         apdus.append(apdu_str[start:i])

#     return apdus

def split_into_real_apdus_le(apdu_str):
    apdus = []
    i = 0
    total_len = len(apdu_str)

    while i + 8 <= total_len:
        start = i
        extended = False

        # Minimum header
        cla = apdu_str[i:i+2]
        ins = apdu_str[i+2:i+4]
        p1  = apdu_str[i+4:i+6]
        p2  = apdu_str[i+6:i+8]

        i += 8

        # If no more bytes → Case 1
        if i == total_len:
            apdus.append(apdu_str[start:i])
            break

        remaining = total_len - i
        next_byte = int(apdu_str[i:i+2], 16)

        # Extended length APDU
        if next_byte == 0x00:
            extended = True

            if i + 6 > total_len:
                raise ValueError("Invalid extended APDU length")

            lc = int(apdu_str[i+2:i+6], 16)
            i += 6
        else:
            lc = next_byte
            i += 2

        data_hex_len = lc * 2

        if i + data_hex_len > total_len:
            raise ValueError("Invalid APDU length (data overflow)")

        i += data_hex_len

        # Check if Le exists
        le_present = False
        if i + 2 <= total_len:
            if (total_len - i) == 2:
                i += 2
                le_present = True

        apdu = apdu_str[start:i]

        # ⭐ ADDITION: if extended APDU and Le not present → append 0000
        if extended and not le_present:
            apdu += "0000"

        apdus.append(apdu)

    return apdus



def APDUhex(apdu_str, title, cborflag=False, checkflag=False, ascii=False, silent=False):

    print("apdu_str", apdu_str)

    full_response = ""

    # FIX: handle already split APDU list
    if isinstance(apdu_str, list):
        apdus = apdu_str
    else:
        apdus = split_into_real_apdus_le(apdu_str)

    for apdu in apdus:

        datafield = apdu[10:] if len(apdu) > 10 else ""

        logging.info(f"[CTAP2.1] :{title}... : {datafield}")
        logging.info(f"[NFC] ---> DATA SENT: {apdu}")

        hex_array = [int(apdu[i:i+2], 16) for i in range(0, len(apdu), 2)]

        # SEND APDU
        if curlserver:
            hexstring, status = curlServerGet(apdu, silent)
            sw1 = status >> 8
            sw2 = status & 0xFF
        else:
            response, sw1, sw2 = connection.transmit(hex_array)
            hexstring = printhexstr(response)

            if ascii and not silent:
                printstr(response)

        logging.info(f"[NFC] <--- DATA RECEIVED: {hexstring}{sw1:02X}{sw2:02X}")

        # APDU transport check
        if sw1 not in (0x90, 0x61):
            sw = f"{sw1:02X}{sw2:02X}"
            logging.error(f"[NFC] APDU FAILED with SW={sw}")
            raise RuntimeError(f"APDU transport failed: SW={sw}")

        full_response += hexstring

        # Handle GET RESPONSE chaining
        while sw1 == 0x61:

            le = sw2 if sw2 != 0x00 else 0xFF
            get_resp = f"80C00000{le:02X}"

            logging.info(f"[NFC] ---> DATA SENT: {get_resp}")

            hex_array = [int(get_resp[i:i+2], 16) for i in range(0, len(get_resp), 2)]

            response, sw1, sw2 = connection.transmit(hex_array)

            chained_hex = printhexstr(response)

            logging.info(f"[NFC] <--- DATA RECEIVED: {chained_hex}{sw1:02X}{sw2:02X}")

            if sw1 not in (0x90, 0x61):
                sw = f"{sw1:02X}{sw2:02X}"
                logging.error(f"[NFC] GET RESPONSE FAILED with SW={sw}")
                raise RuntimeError(f"GET RESPONSE failed: SW={sw}")

            if ascii and not silent:
                printstr(response)

            full_response += chained_hex

    # CTAP status extraction
    if len(full_response) == 0:
        logging.info("[CTAP] Empty payload received")
        return "", "00"

    possible_status = full_response[:2]

    if possible_status == "00":
        ctap_status = possible_status
        payload = full_response[2:]
    else:
        ctap_status = "00"
        payload = full_response

    #logging.info(f"[CTAP] STATUS = {ctap_status}")

    return full_response, possible_status


def APDUhexExtended(s, title, cborflag=False, checkflag=False, ascii=False, silent=False):
    full_response = ""
    sw1, sw2 = 0x00, 0x00

    if title and s.startswith("80") and len(s) > 10:
        datafield = s[10:]
        #logging.info(f"[CTAP2.1] :{title}... : {datafield}")

    logging.info(f"[NFC] ---> DATA SENT: {s}")

    hex_array = [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

    if curlserver:
        hexstring, status = curlServerGet(s, silent)
        sw1, sw2 = status >> 8, status & 0xFF
        full_response = hexstring
    else:
        response, sw1, sw2 = connection.transmit(hex_array)
        response_hex = printhexstr(response)
        full_response += response_hex
        status = (sw1 << 8) | sw2

        if ascii and not silent:
            printstr(response)

        logging.info(f"[NFC] <--- DATA RECEIVED: {response_hex}{format(sw1, '02X')}{format(sw2, '02X')}")

    # 🔄 Handle SW1 = 0x61: more data is available
    while sw1 == 0x61:
        le = sw2 if sw2 != 0x00 else 0xFF  # If SW2 is 0x00, use 0xFF as length
        get_response_apdu = "80C00000" + format(le, '02X')
        logging.info(f"[NFC] ---> DATA SENT: {get_response_apdu}")

        hex_array = [int(get_response_apdu[i:i+2], 16) for i in range(0, len(get_response_apdu), 2)]
        response, sw1, sw2 = connection.transmit(hex_array)
        chained_hex = printhexstr(response)
        full_response += chained_hex

        if ascii and not silent:
            printstr(response)

        #logging.info(f"[NFC] <--- DATA RECEIVED: {chained_hex}{format(sw1, '02X')}{format(sw2, '02X')}")
        status = (sw1 << 8) | sw2

    # ✅ Final logging
    #if not silent:
        #if status == 0x9000:
            #logging.info("[NFC] FINAL STATUS: 0x9000 (SUCCESS)")
       # else:
            #logging.error(f"[NFC] FAILED STATUS: 0x{format(status, '04X')}")

        #if cborflag:
           # hex_string_to_cbor_diagnostic(full_response)

        # Log final full response
        formatted = f"RECEIVED: {full_response}{format(sw1, '02X')}{format(sw2, '02X')}"
        #logging.info(formatted)
       # print(formatted)

    return full_response, status


##########
# Makes pretty CBOR diagnostic output very nice
##########
def hex_string_to_cbor_diagnostic(hex_string):
    byte_array = bytes.fromhex(hex_string)
    cbor_data = cbor2.loads(byte_array)
    json_string = json.dumps( cbor_data, cls=CustomEncoder, indent=4)
   # printcolor(CYAN,"CBORs Diagnostic format:")
    #printcolor(CYAN,json_string)


################
# When a Applete is installed on an Applet the Initialization is done
# But we are using a simulator and loading it so basically install.
################
def initSimulator():
    APDUhex("00A4040008A0000006472F000100", "Select Applete", silent=True)
    APDUhex("80500000085B65A8ED5854176C00","Initialize Update", silent=True)
    APDUhex("848200001003F7BEED74AE38443D8385BE202346A8","External Authenticate", silent=True)

    APDUhex("004200001000000000000000000000000000000000","Set AAGUID to zeros")
    
    result, status= APDUhex("004100002095DFE1E13B3F535D9D65967CB35E730E03CC023CBB7DC75CB640A7B76F02164D","Set Attestation privatekey", silent=True)
    if (status ==  0x6D00):
        printcolor(ORANGEBLACK,f"0x{status:04X} The card is assumed initialized with this error. Set private key failed, it is already set:")
        return;

    printcolor(CYAN,"======Set Attestatin Cert======")
    APDUhex("1040000080308202763082021DA0030201020202101A300A06082A8648CE3D040302308199310B30090603550406130255533113301106035504080C0A4E6577204A65727365793111300F06035504070C08536F6D6572736574311A3018060355040A0C11436F6D706F5365637572652C20496E632E31223020060355040B0C1941757468", "Certificate part 1", silent=True)

    APDUhex("1040000080656E74696361746F72204174746573746174696F6E3122302006035504030C19436F6D706F536563757265204649444F3220526F6F742043413020170D3232303930393036353132355A180F32303532303930313036353132355A30818E310B30090603550406130255533113301106035504080C0A4E6577204A6572736579", "Certificate part 2", silent=True)

    APDUhex("10400000803111300F06035504070C08536F6D6572736574311A3018060355040A0C11436F6D706F5365637572652C20496E632E31223020060355040B0C1941757468656E74696361746F72204174746573746174696F6E3117301506035504030C0E417263756C7573204649444F20323059301306072A8648CE3D020106082A8648CE3D", "Certificate part 3", silent=True)

    APDUhex("104000008003010703420004306380DABA7B87D2E4F2BA51AA3436F8EF6494D9C4C967A44B7C96E0C4AA6181E1B670F8A7BFE87B7BD97AD0EBAFD9E362CECF666D60C90593D8D9D95310561BA35C305A30090603551D1304023000300B0603551D0F0404030205E0301D0603551D0E04160414C70368B89F5EC242A1E10824F83E865E36DA", "Certificate part 4", silent=True)
 
    APDUhex("004000007A42E23021060B2B0601040182E51C010104041204109D3DF6BA282F11EDA2610242AC120002300A06082A8648CE3D040302034700304402205460E9FE0017D25213C62845ABD1AB80AE5159234CCB8C04D486B8538445B5AB0220567E359CA16D4CC2FBD5F4B30DDFDBC9AF5B9EABBD2A76B9F4ADD3842A21401A", "Certificate part 5 the end", silent=True)




# Chaining logic reused
def build_chained_apdus(payload_bytes, chunk_size=255, log_chunks=True, max_log_chunks=5):
    apdus = []
    offset = 0
    total = len(payload_bytes)
    chunk_index = 0

    while offset < total:
        chunk = payload_bytes[offset: offset + chunk_size]
        lc = f"{len(chunk):02X}"

        # Set CLA: 90 for chained chunks, 80 for last chunk
        is_last_chunk = (offset + chunk_size >= total)
        cla = "80" if is_last_chunk else "90"
        apdu = cla + "100000" + lc + chunk.hex().upper()
        apdus.append(apdu)

        if log_chunks and chunk_index < max_log_chunks:
            util.printcolor(util.BLUE, f"Data Sent (chunk {chunk_index + 1}): {apdu}")

        offset += chunk_size
        chunk_index += 1

    return apdus
    
def ConnectJavaCard():
    global connection, curlserver, args
    parseCmdline()
    
    if args.curl == 'on':
        printcolor(ORANGEBLACK, " Java Card is Curl TestServer at port :8080 ")
        curlserver = True
        printcolor(ORANGEBLACK, " Initialize card for Desktop JVM usage ")
        initSimulator()
        printcolor(ORANGEBLACK, "End Initialize card for Desktop JVM usage")
        return None  # or a mock connection if needed
    else:
        printcolor(REDWHITE, " Using real Java Card (not Curl TestServer)")        
    
    r = readers()
    if not r:
        printcolor(REDWHITE, "There is no USB token connected. Please connect one.")
        return None

    for line in r:
        print(line)

    connection = r[0].createConnection()
    connection.connect()
    return connection 


# util.py

def extractCBORMap(response):
    if len(response) > 6:
        result = response[2:]
    else:
        result = ""
    return result

def getInfoMaximumCredsCountsInteger(response: str) -> int:
    global maxAllowedCredCount
    maxAllowedCredCount = extractResponseCBOR(response, "20")
    return maxAllowedCredCount
    
def extract_scenario(SCENARIO):
    result = SCENARIO.split(":", 2)[-1].strip()
    cleaned = " ".join(result.split())
    return format_semicolons(cleaned)

# def split_after_first_semicolon(s):
#     parts = s.split(";", 1)  # split only once
#     return "\n\n".join(part.strip() for part in parts)

def format_semicolons(s):
    parts = s.split(";")

    if not parts:
        return s

    # First split → double newline
    result = parts[0].strip()

    if len(parts) > 1:
        result += "\n\n" + parts[1].strip()

    # Remaining splits → single newline
    for part in parts[2:]:
        result += "\n" + part.strip()

    return result


import binascii
def extractResponseCBOR(hex_response: str, requestKey: str):
    """
    Input  : CTAP2 response as HEX string
    Output : Prints full CBOR tree and prints & returns requested key value
    """

    found_value = None

    def dump(value, indent=0):
        nonlocal found_value
        pad = "  " * indent

        if isinstance(value, dict):
            # print(f"{pad}MAP ({len(value)})")
            for k, v in value.items():
                # if isinstance(k, int):
                #     key_str = format(k, 'X')
                # else:
                #     key_str = str(k)
                # print(f"{pad}  KEY [{type(k).__name__}] = {k}")

                # ---- Match requested key ----
                if str(k) == requestKey:
                    found_value = v

                dump(v, indent + 2)

        elif isinstance(value, list):
            # print(f"{pad}ARRAY ({len(value)})")
            for i, item in enumerate(value):
                # print(f"{pad}  INDEX {i}")
                dump(item, indent + 2)

      

       

    # ---- Decode CTAP2 response ----
    raw = binascii.unhexlify(hex_response)

    if not raw:
        raise ValueError("Empty response")

    status = raw[0]
    # print(f"CTAP2 STATUS = 0x{status:02X}")

    if status != 0x00:
        # print("CTAP2 error response — no CBOR payload")
        return None

    if len(raw) == 1:
        # print("No CBOR payload present")
        return None

    decoded = cbor2.loads(raw[1:])

    # print("\nCBOR DECODED STRUCTURE")
    # print("---------------------")
    dump(decoded)

    # ---- Handle result inside function ----
    # print("\nRESULT")
    # print("------")

    return found_value

def ResetCardPower():
    """
    This function performs a power cycle of the Java Card using the smartcard library.
    Make sure your reader supports power cycling via disconnect/connect.
    """
    from smartcard.System import readers
    import time

    r = readers()
    if len(r) == 0:
        raise Exception("No smart card readers found.")

    reader = r[0]
    connection = reader.createConnection()

    try:
        # Disconnect the card to simulate power down
        connection.disconnect()
        print("🔌 Card disconnected.")
    except Exception as e:
        print("⚠️ Disconnect failed or not supported:", str(e))

    time.sleep(1.0)  # Delay to simulate power off

    try:
        # Reconnect the card to simulate power up
        connection.connect()
        print("⚡ Card reconnected (power cycle complete).")
    except Exception as e:
        raise Exception("❌ Failed to reconnect to card: " + str(e))
    







def pad_pin_P1(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    if validate:
        if len(pin_bytes) < 4:
            raise ValueError("PIN must be at least 4 bytes")
        if len(pin_bytes) > 64:
            raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def wrongPad_pinP1(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_padded = pin.encode('utf-8').ljust(64, b"\x00")

    # Step 2: make it mutable
    out = bytearray(pin_padded)

    util.printcolor(util.YELLOW, f"original padded PIN: {out.hex()}")

    # Step 3: insert invalid bytes (AB CD) at position 16
    # This breaks the padding while keeping the total length = 64
    out[16:18] = bytes.fromhex("ABCD")

    util.printcolor(util.YELLOW, f"corrupted padded PIN: {bytes(out).hex()}")

    # Step 4: return corrupted 64-byte padded pin
    return bytes(out)

def pad_pin_P1Lengthnot(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    

    return pin_bytes.ljust(32, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes





def aes256_cbc_encryptP1(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes256_cbc_encryptWrongLengthPaddedPIN(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def hmac_sha256P1(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def encapsulate_protocolP1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 1,   # crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

def encapsulate_protocolkeyP1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = [
        2,    # kty: EC2
        -25,  # alg: -25 (not actually used)
        -1,   # crv: P-256
        int2bytes(pub.x, 32),
        int2bytes(pub.y, 32),
    ]
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret
def invalidSharesecret(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 1,   # crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    print("share secret:",shared_secret.hex())
    bad_shared_secret = bytearray(shared_secret)
    bad_shared_secret[0] ^= 0xFF
    bad_shared_secret = bytes(bad_shared_secret)
    return key_agreement, bad_shared_secret

def invalidcoskey(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 8,   # wrong crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    
    return key_agreement, shared_secret


def aes256_cbc_decryptP1(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

def aes256_cbc_encryptWithoutPad(shared_secret, data):
    # Calculate the number of padding bytes needed
    padding_needed = 16 - (len(data) % 16)
    # Only pad if data length is not already a multiple of 16

    if padding_needed != 16:
        data += b'\x00' * padding_needed
        

    iv = os.urandom(16)




# Spec says IV(0)  but we will not do that!!!!
#    iv = b'\x00' * 16  # 16-byte IV of all zeroes As per spec FIDO


    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt without padding (data should be a multiple of block size, 16 bytes for AES)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    # strCipher = util.toHex(ciphertext)
    # strIV = util.toHex(iv)
    # util.printcolor(util.YELLOW, f"ciphertext -> {strCipher}")
    # util.printcolor(util.YELLOW, f"IV -> {strIV} ")

    return iv + ciphertext

def aes256_cbc_encryptWithoutpaddedP1(shared_secret, data):
    # Calculate the number of padding bytes needed
    padding_needed = 16 - (len(data) % 16)
    # Only pad if data length is not already a multiple of 16

    # if padding_needed != 16:
    #     data += b'\x00' * padding_needed
    util.printcolor(util.YELLOW, f"  Without padding pin:{padding_needed}")
    iv = os.urandom(16)


def pad_pinlengthnotmatch(pin: str) -> bytes:
    """
    Creates an INVALID paddedNewPin to trigger CTAP1_ERR_INVALID_PARAMETER.
    Returns a value that is NOT 64 bytes long.
    """
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")

    # Wrong padding: only pad to 32 bytes (NOT 64)
    pin_padded = pin.encode().ljust(32, b"\0")

    util.printcolor(util.YELLOW,f" Invalid ppaddedPin Length: {pin_padded.hex()}") 
    return pin_padded

def APDUhexUI(s, title, cborflag=False, checkflag=False, ascii=False, silent=False):
    full_response = ""
    if title and s.startswith("80") and len(s) > 10:
        datafield = s[10:]
        logging.info(f"[CTAP2.1] :{title}... : {datafield}")
 
    #logging.info(f"[CTAP2.1] {title}: ---> Sending CTAP CMD... {s}")
    logging.info(f"[NFC] ---> DATA SENT: {s}")
 
    hex_array = [int(s[i:i+2], 16) for i in range(0, len(s), 2)]
    hexstring = None
    status = 0
 
    if curlserver:
        hexstring, status = curlServerGet(s, silent)
        sw1, sw2 = status >> 8, status & 0x00FF
    else:
        response, sw1, sw2 = connection.transmit(hex_array)
        hexstring = printhexstr(response)
        full_response += hexstring
        if ascii and not silent:
            printstr(response)
        status = (sw1 << 8) | sw2
 
    logging.info(f"[NFC] <--- DATA RECEIVED: {hexstring}{format(sw1, '02X')}{format(sw2, '02X')}")
 
    # Handle SW1 == 0x61 (chaining)
    while sw1 == 0x61:
        le = sw2 if sw2 != 0x00 else 0xFF
        get_response_apdu = "80C00000" + format(le, '02X')
        logging.info(f"[NFC] ---> DATA SENT: {get_response_apdu}")
 
        hex_array = [int(get_response_apdu[i:i+2], 16) for i in range(0, len(get_response_apdu), 2)]
        response, sw1, sw2 = connection.transmit(hex_array)
        chained_hex = printhexstr(response)
        full_response += chained_hex
        logging.info(f"[NFC] <--- DATA RECEIVED: {chained_hex}{format(sw1, '02X')}{format(sw2, '02X')}")
 
        if ascii and not silent:
            printstr(response)
 
        status = (sw1 << 8) | sw2
 
    # Final logging
   # if not silent:
        #if status == 0x9000:
          #  logging.info("[NFC] FINAL STATUS: 0x9000 (SUCCESS)")
       ## else:
           # logging.error(f"[NFC] FAILED STATUS: 0x{format(status, '04X')}")
 
        #if cborflag:
          #  hex_string_to_cbor_diagnostic(full_response)
 
    return full_response, status

def run_apdu(apdu, title, expected_prefix=None, expected_error_name=None):

    # ==============================
    # 🔹 Case 1: If APDU is hex string
    # ==============================
    if isinstance(apdu, str):

        apdu = apdu.replace(" ", "").replace("\n", "")

        # detect long APDU
        if len(apdu) > 10:

            header = apdu[:8]   # CLA INS P1 P2
            lc = int(apdu[8:10], 16)
            data = apdu[10:]

            data_len = len(data) // 2

            if data_len >255:

                chunks = []
                offset = 0

                while offset < data_len:

                    chunk_data = data[offset*2:(offset+255)*2]
                    chunk_len = len(chunk_data) // 2

                    cla = int(header[:2], 16)

                    # set chaining bit for intermediate chunks
                    if offset + chunk_len < data_len:
                        cla = cla | 0x10

                    chunk_apdu = (
                        f"{cla:02X}" +
                        header[2:] +
                        f"{chunk_len:02X}" +
                        chunk_data
                    )

                    chunks.append(chunk_apdu)

                    offset += chunk_len

                apdu = chunks

    # ==============================
    # 🔹 Case 2: Chained APDU (list)
    # ==============================
    if isinstance(apdu, list):

        for i, chunk in enumerate(apdu):

            is_last = (i == len(apdu) - 1)

            response, status = APDUhexUI(
                chunk,
                f"{title} (chunk {i+1})"
            )

            if is_last:
                return _validate_response(
                    response,
                    status,
                    title,
                    expected_prefix,
                    expected_error_name
                )

        return response, status

    # ==============================
    # 🔹 Case 3: Normal APDU
    # ==============================
    else:

        response, status = APDUhexUI(apdu, title)

        return _validate_response(
            response,
            status,
            title,
            expected_prefix,
            expected_error_name
        )

# def run_apdu(apdu, title, expected_prefix=None, expected_error_name=None):
 
#     # ==============================
#     # 🔹 Case 1: Chained APDU (list)
#     # ==============================
#     if isinstance(apdu, list):
 
#         for i, chunk in enumerate(apdu):
 
#             is_last = (i == len(apdu) - 1)
 
#             response, status = APDUhexUI(
#                 chunk,
#                 f"{title} (chunk {i+1})"
#             )
 
#             # Only validate final chunk
#             if is_last:
#                 return _validate_response(
#                     response,
#                     status,
#                     title,
#                     expected_prefix,
#                     expected_error_name
#                 )
 
#         return response, status
 
#     # ==============================
#     # 🔹 Case 2: Single APDU
#     # ==============================
#     else:
 
#         response, status = APDUhexUI(apdu, title)
 
#         return _validate_response(
#             response,
#             status,
#             title,
#             expected_prefix,
#             expected_error_name
#         )
def _validate_response(response,
                       status,
                       title,
                       expected_prefix,
                       expected_error_name):
 
    # Special case: 0x6A80
    if status == 0x6A80:
        printcolor(
            GREEN,
            f"✅ {title} Passed — Error code: "
            f"{expected_error_name} (0x{expected_prefix})"
        )
        return response, status
 
    # Transport failure
    if status != 0x9000:
        printcolor(RED,
            f"❌ {title} Transport Failed, SW=0x{status:04X}"
        )
        exit(0)
 
    # CTAP validation
    if expected_prefix:
        if not response.startswith(expected_prefix):
            printcolor(
                RED,
                f"❌ {title} Failed, response={response}"
            )
            exit(0)
 
        if expected_error_name:
            printcolor(
                GREEN,
                f"✅ {title} Passed — Error code: "
                f"{expected_error_name} (0x{expected_prefix})"
            )
        else:
            printcolor(GREEN, f"✅ {title} Passed")
 
    return response, status


def run_apduu2f(apdu, title,expected_prefix=None,expected_error_name=None):
 
    response, status = APDUhexu2f(apdu, title)
 
    if status != 0x9000:
        printcolor(RED, f"❌ {title} Transport Failed, SW=0x{status:04X}")
        exit(0)
       
 
    if expected_prefix:
        if not response.startswith(expected_prefix):
            printcolor(
                RED,
                f"❌ {title} Failed, response={response}"
            )
            exit(0)
 
        if expected_error_name:
            printcolor(
                GREEN,
                f"✅ {title} Passed — Error code: {expected_error_name} (0x{expected_prefix})"
            )
        else:
            printcolor(GREEN, f"✅ {title} Passed")
 
    return response, status



def APDUhexu2f(s, title, cborflag=False, checkflag=False, ascii=False, silent=False):
    full_response = ""
    if title and s.startswith("80") and len(s) > 10:
        datafield = s[10:]
        logging.info(f"[CTAP2.1] :{title}... : {datafield}")
 
    #logging.info(f"[CTAP2.1] {title}: ---> Sending CTAP CMD... {s}")
    logging.info(f"[NFC] ---> DATA SENT: {s}")
 
    hex_array = [int(s[i:i+2], 16) for i in range(0, len(s), 2)]
    hexstring = None
    status = 0
 
    if curlserver:
        hexstring, status = curlServerGet(s, silent)
        sw1, sw2 = status >> 8, status & 0x00FF
    else:
        response, sw1, sw2 = connection.transmit(hex_array)
        hexstring = printhexstr(response)
        full_response += hexstring
        if ascii and not silent:
            printstr(response)
        status = (sw1 << 8) | sw2
 
    logging.info(f"[NFC] <--- DATA RECEIVED: {hexstring}{format(sw1, '02X')}{format(sw2, '02X')}")
 
    # Handle SW1 == 0x61 (chaining)
    while sw1 == 0x61:
        le = sw2 if sw2 != 0x00 else 0xFF
        get_response_apdu = "00C00000" + format(le, '02X')
        logging.info(f"[NFC] ---> DATA SENT: {get_response_apdu}")
 
        hex_array = [int(get_response_apdu[i:i+2], 16) for i in range(0, len(get_response_apdu), 2)]
        response, sw1, sw2 = connection.transmit(hex_array)
        chained_hex = printhexstr(response)
        full_response += chained_hex
        logging.info(f"[NFC] <--- DATA RECEIVED: {chained_hex}{format(sw1, '02X')}{format(sw2, '02X')}")
 
        if ascii and not silent:
            printstr(response)
 
        status = (sw1 << 8) | sw2
 
    # Final logging
   # if not silent:
        #if status == 0x9000:
          #  logging.info("[NFC] FINAL STATUS: 0x9000 (SUCCESS)")
       ## else:
           # logging.error(f"[NFC] FAILED STATUS: 0x{format(status, '04X')}")
 
        #if cborflag:
          #  hex_string_to_cbor_diagnostic(full_response)
 
    return full_response, status
 