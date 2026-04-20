import util
import os
import hashlib
import cbor2
import clientprotocol1

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256
from textwrap import wrap

import util
import binascii
import cbor2
import hashlib, hmac
import os
from textwrap import wrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import cbor2
import binascii
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import util
import getasserationrequest


def cardReset():
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    util.APDUhex("80100000010700", "Card Reset")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
##### case 1

def authenticatorClientPin():
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        Send a valid CTAP2 authenticatorClientPin(0x01) message with getKeyAgreement(0x02) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "keyAgreement" field, and its of type MAP
            (b) in COSE "keyAgreement" field:
                (1) check that public key is EC2(kty(1) is set to 2) 
                (2) check that key crv(-1) curve field that is set to P256(1)
                (3) check that key alg(3) is set to ECDH-ES+HKDF-256(-25)
                (4) check that key contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) check that key contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (6) check that key does NOT contains ANY other coefficients.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("801080000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True)


###### case 2
def makecredential(clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg a valid "hmac-secret" set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, with extensions payload containing 'hmac-secret' field set to true.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    apdu=createCBORmakeCred(clientDataHash, rp, user)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result
##### case 3

def getAsseration(pin,rp, response):

    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: P-3
        Send a valid CTAP2 getAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with one salt, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) Check that response contains extensions encrypted "hmac-secret" extension response. Decrypt it and save it as salt1
            (b) Send another GetAssertion with salt1 and salt2, and check that response still equal to result, and nonUvSalt2Hmac does not equal nonUvSalt1Hmac.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    pinToken, sharedSecret, keyAgreement = getPINtokenAndSharedSecret(pin)
    # Prepare extension hmac-secret with 1 salt
    salt1 = os.urandom(32)
    saltEnc = aes256_cbc_encrypt(sharedSecret, salt1)
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]
    getAssertionWithHMACSecret(pin, clientDataHash, rp, credId, keyAgreement,saltEnc,saltAuth )
    ###adding two salt
    util.ResetCardPower()
    util.ConnectJavaCard()
        
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    pinToken, sharedSecret, keyAgreement = getPINtokenAndSharedSecret(pin)
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    combined_salts = salt1 + salt2
    # Encrypt (sharedSecret, salt1 || salt2)
    saltEnc = aes256_cbc_encrypt(sharedSecret, combined_salts)
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]
    getAssertionWithHMACSecret(pin, clientDataHash, rp, credId, keyAgreement,saltEnc,saltAuth )
##### case 4
def supporingSalt1and2(pin,rp, response):
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: P-4:
        Send a valid CTAP2 GetAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with salt1 and salt2, wait for the response, and:
            (a) Check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
            (b) Check that response extensions contain "hmac-secret" extension. Decrypt extensions
            (c) Check that decrypted hmacs contain uvSalt1Hmac, and uvSalt2Hmac
            (d) Check that uvSalt1Hmac does not equal to nonUvSalt1Hmac, an uvSalt2Hmac does not equal to nonUvSalt2Hmac.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    pinToken, sharedSecret, keyAgreement = getPINtokenAndSharedSecret(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    combined_salts = salt1 + salt2
    # Encrypt (sharedSecret, salt1 || salt2)
    saltEnc = aes256_cbc_encrypt(sharedSecret, combined_salts)
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]
    getAsserationcomineSalt(pin, clientDataHash, rp, pinAuthToken,credId, keyAgreement,saltEnc,saltAuth )

#####failed case 1
def randomHMAC(pin,rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: F-1:
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg "hmac-secret" set to a random type, wait for the response, and check that Authenticator returns an error.""")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")   
    clientDataHash = os.urandom(32);
    pinToken = clientprotocol1.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    apdu=createMakeCred(clientDataHash, rp, user)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result


###### failed case 2
def hmaconesalt(pin,rp, user,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: F-2:
        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret" extension request with one salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""") 
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    pinToken, sharedSecret, keyAgreement = getPINtokenAndSharedSecret(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    #lessthan  32 byte
    salt1 = os.urandom(10)
 
    saltEnc = aes256_cbc_encrypt(sharedSecret,  salt1 )
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]
    getAsserationcomineSalt(pin, clientDataHash, rp,pinAuthToken, credId, keyAgreement,saltEnc,saltAuth )


#### failed case 3

def hmaconesaltandsalt2(pin,rp, user,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret ****")
    util.printcolor(util.YELLOW, """Test started: F-3:
        Send a CTAP2 getAssertion(0x02) message, with "extensions" containg a "hmac-secret" extension request with two salts, with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""") 
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    pinToken, sharedSecret, keyAgreement = getPINtokenAndSharedSecret(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    #lessthan  32 byte
    salt1 = os.urandom(32)
    salt2 = os.urandom(10)
    combined_salts = salt1 + salt2
 
    saltEnc = aes256_cbc_encrypt(sharedSecret,  combined_salts)
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]
    getAsserationcomineSalt(pin, clientDataHash, rp,pinAuthToken, credId, keyAgreement,saltEnc,saltAuth )






def createCBORmakeCred(clientDataHash, rp, user):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
           "id": rp,  # id: unique identifier
         "name": rp,  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        
    ]

    extensions={"credProtect": 1,
    "hmac-secret":True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_extensions          = cbor2.dumps(extensions).hex().upper()
   
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06"+ cbor_extensions
    #dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand



def createMakeCred(clientDataHash, rp, user):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
           "id": rp,  # id: unique identifier
         "name": rp,  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        
    ]

    extensions={
    "hmac-secret":[]}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_extensions     = cbor2.dumps(extensions).hex().upper()
   
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06"+ cbor_extensions
    #dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand

def getAsserationcomineSalt(pin, clientDataHash, rpId,pinAuthToken,credId_hex,keyAgreement,saltEnc,saltAuth ):
   

    # Prepare allowList
    allow_list = [{
        "id": bytes.fromhex(credId_hex),
        "type": "public-key"
    }]

    

    hmac_secret_extension = {
        0x01: keyAgreement,
        0x02: saltEnc,
        0x03: saltAuth,
        0x04: 1
    }

    # Prepare GetAssertion CBOR MAP
    cbor_map = {
        1: rpId,                        # rpId
        2: clientDataHash,              # clientDataHash
        3: allow_list,                  # allowList
        4: {"hmac-secret": hmac_secret_extension},
        5:{},
        6:pinAuthToken,
       # 6: hmac_sha256(pinToken, clientDataHash)[:16],  # pinAuth
        7: 1  # pinProtocol = 1
    }
    data = cbor2.dumps(cbor_map)
    payload = b"\x02" + data
    apdus = build_apdu_chain(payload)

    # Send chained APDU
    for i, apdu in enumerate(apdus):
        util.APDUhex(apdu, "GetAssertion (chained)" if i < len(apdus)-1 else "GetAssertion Final", checkflag=(i == len(apdus)-1))




def getAssertionWithHMACSecret(pin, clientDataHash, rpId, credId_hex,keyAgreement,saltEnc,saltAuth ):
   

    # Prepare allowList
    allow_list = [{
        "id": bytes.fromhex(credId_hex),
        "type": "public-key"
    }]

    

    hmac_secret_extension = {
        0x01: keyAgreement,
        0x02: saltEnc,
        0x03: saltAuth
        # 0x04 omitted (pinProtocol = 1 implicit)
    }

    # Prepare GetAssertion CBOR MAP
    cbor_map = {
        1: rpId,                        # rpId
        2: clientDataHash,              # clientDataHash
        3: allow_list,                  # allowList
        4: {"hmac-secret": hmac_secret_extension},
       # 6: hmac_sha256(pinToken, clientDataHash)[:16],  # pinAuth
        7: 1  # pinProtocol = 1
    }
    data = cbor2.dumps(cbor_map)
    payload = b"\x02" + data
    apdus = build_apdu_chain(payload)

    # Send chained APDU
    for i, apdu in enumerate(apdus):
        util.APDUhex(apdu, "GetAssertion (chained)" if i < len(apdus)-1 else "GetAssertion Final", checkflag=(i == len(apdus)-1))


def getPINtokenAndSharedSecret(pin):
    util.APDUhex("80100000010400", "GetInfo")
    response, status = util.APDUhex("801080000606A20101020200", "Client PIN getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    keyAgreement, sharedSecret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(sharedSecret, pin_hash)

    cbor_map = {
        1: 1,
        2: 5,
        3: keyAgreement,
        6: pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN getPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)
    pin_token = aes256_cbc_decrypt(sharedSecret, enc_pin_token)
    return pin_token, sharedSecret, keyAgreement


def build_apdu_chain(payload: bytes):
    full_hex = payload.hex().upper()
    max_chunk_size = 255 * 2
    chunks = [full_hex[i:i + max_chunk_size] for i in range(0, len(full_hex), max_chunk_size)]
    apdus = []

    for i, chunk in enumerate(chunks):
        cla = "90" if i < len(chunks) - 1 else "80"
        apdu = f"{cla}108000{len(chunk)//2:02X}{chunk}"
        apdus.append(apdu)
    return apdus


def encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,
        3: -25,
        -1: 1,
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key.get(-2))
    peer_y = bytes2int(peer_cose_key.get(-3))
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()
    return key_agreement, shared_secret


def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    return encryptor.update(data) + encryptor.finalize()


def aes256_cbc_decrypt(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def int2bytes(val, length):
    return val.to_bytes(length, 'big')


def bytes2int(b):
    return int.from_bytes(b, 'big')














   