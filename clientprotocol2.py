import util
import binascii
import cbor2
import make_credential_request
import logging
import sys
import os
import getasserationrequest
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("fido_test_log.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
def authenticatorClientPin():
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Send a valid CTAP2 authenticatorClientPin(0x01) message with getKeyAgreement(0x02) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "keyAgreement" field, and its of type MAP
            (b) in COSE "keyAgreement" field:
                (1) check that public key is EC2(kty(1) is set to 2) 
                (2) check that key crv(-1) curve field that is set to P256(1)
                (3) check that key alg(3) is set to ECDH-ES+HKDF-256(-25)
                (4) check that key contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) check that key contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (6) check that key does NOT contains ANY other coefficients""");

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
    util.APDUhex("00a4040008a0000006472f0001","Select applet") 
    util.APDUhex("80108000010700","Reset Card PIN")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")                                      
    util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    util.APDUhex("80108000010700","Reset Card PIN")

def setpin_protocol2(pin):
    # util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    # util.printcolor(util.YELLOW,"""Test started: P-1
    #     Generate a shared key by deriving sharedSecret from previously obtained keyAgreement, and set new random clientPin""");
    setpin.clientPinSet(pin)


def changePin_protocol2(oldpin, newpin):
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Change current pincode to the new pincode.""");
    
    changePin(oldpin, newpin)

def change_client_pin_swapping_protocol2(old_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    util.printcolor(util.YELLOW,"KEY AGREEMENT BY PROTOCOL 1 -> CHANGE PIN BY PROTOCOL 2")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response, status

def changePin(old_pin, new_pin):
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])
    print("Shared Secret Protocol 2 => "+util.toHex(sharedSecret))

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:16]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)


def createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu


def pinToken_protocol2(pin):
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Get a valid pinAuth token.""");
    make_credential_request.getPINtokenPubkey(pin)



def makecred_protocol2(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""");
    result = make_credential_request.makeCred(curpin, clientDataHash, rp, user)
    return result
    


def getAsseration_protocol2(curpin, clientDataHash, rp,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-3
    Send a valid CTAP2 authenticatorGetAssertion(0x02) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""");
    getasserationrequest.makeAssertion(curpin, clientDataHash, rp, credId);


def pintokenWithPermission(curpin, rp,permission):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Get a valid pinUVAuthToken with permissions.""");       
    getPINtokenPubkey(curpin,rp, permission);

def pintokenWithPermissionMakeCredential(curpin, rp,permission,clientDataHash,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""");       
    pinToken, pubkey= getPINtokenPubkey(curpin,  rp, permission);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = make_credential_request.createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result


def pintokenWithPermissionAsseration(curpin, rp,permission,clientDataHash,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-3
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""");       
    pinToken, pubkey= getPINtokenPubkey(curpin,  rp, permission);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    apdu = getasserationrequest.createCBORmakeAssertion(clientDataHash,rp, pinAuthToken, credId)
    result = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result



def clientPinSetMinimumPinLength(curpin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Try setting new pin, that is of size between minPINLength+1 and 63 characters, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00)""");       
    setpin.clientPinSet(curpin)


def clientPinSetLessthan4byte(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: F-1
        Try setting new pin, that is less than 4 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37).""");       
    setpin.clientPinSet(pin)



def clientPinSetbiggerThan63(pin):
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: F-2
        Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns an error.""");       
    setpin.clientPinSet(pin)


def clientPinSetexactly64(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: F-3
        Try setting new pin, that is exactly 64 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37).""");       
    setpin.clientPinSet(pin)



def retriesCount():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getPINRetries(0x01) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "pinRetries" field
            (b) authenticatorClientPin_Response.pinRetries is of type NUMBER
            (c) authenticatorClientPin_Response.pinRetries is max of 8!.""");  
    pinRetriescount()

def pinauthBlocked(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Send two CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that each request fails with error CTAP2_ERR_PIN_INVALID(0x31)
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getPINRetries(0x01) subCommand, and check that pinRetries have decreased by two
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED(0x34).""");  
    getPINtokenPubkeyblocked(pin)
    getPINtokenPubkeyblocked(pin)
    pinRetriescount()
    getPINtokenPubkeyblocked(pin)
    
    
def pinretriesBlocked(pin,user,clientDataHash,rp):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 2****")
    util.printcolor(util.YELLOW,"""Test started: P-3 
        Register a valid authenticatorMakeCred(0x01) using the valid PIN. Check that pinRetries counter is reset and back to the original retries counter.
        Keep sending getPINToken with invalid pin until pinRetries counter is 0.
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains valid pinCode, and check that authenticator returns error CTAP2_ERR_PIN_BLOCKED(0x32).""");  
    result = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    #pinToken, pubkey = make_credential_request.getPINtokenPubkey("654321")
    
    checkRetriesCount(pin)

    return result

def getPINtokenPubkeys(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken3(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    




def createGetPINtoken3(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand





def checkRetriesCount(pin):
    retries = retriesCount()
    retries = 8  # Starting with 8 retries (manual loop)
    
    for i in range(retries):
        print(f"\n--- Attempt {i + 1} ---")

        try:
            util.ResetCardPower()
            util.ConnectJavaCard()

            # Attempt to get PIN token with wrong PIN
            response = getPINtokenPubkeys("654321")
            print("Response:", response)
        except Exception as e:
            print(f"getPINtoken() Exception: {e}")

        try:
            retry_count = pinRetriescount()
            print(f"Remaining PIN retries: {retry_count}")
            if retry_count == 0:
                print("PIN is blocked (CTAP2_ERR_PIN_AUTH_BLOCKED). Stopping test.")
                break
        except Exception as e:
            print(f"retriesCount() Exception: {e}")







def getPINtokenPubkeyblocked(curpin):
    
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = make_credential_request.createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    
    






def retriesCount1():
    response, status = util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
    cbor_data = cbor2.loads(binascii.unhexlify(response[2:])) 
    pin_retries = cbor_data[0x03]
    if pin_retries > 8:
        util.printcolor(util.RED, f" Invalid 'pinRetries': {pin_retries}. Maximum allowed is 8.")
        return
    util.printcolor(util.GREEN, f"✅ Test Passed: pinRetries = {pin_retries}")


def pinRetriescount():
    util.APDUhex("00A4040008A0000006472F0001", "Select FIDO Applet")
    response, status = util.APDUhex("801000000606A20102020100", "ClientPIN GetRetries", checkflag=True)
    cbor_data = cbor2.loads(binascii.unhexlify(response[2:])) 
    pin_retries = cbor_data[0x03]
    if not isinstance(pin_retries, int):
        util.printcolor(util.RED, f"'pinRetries' is not a number. Got type: {type(pin_retries)}")
        return
    if pin_retries > 8:
        util.printcolor(util.RED, f" Invalid 'pinRetries': {pin_retries}. Maximum allowed is 8.")
        return
    util.printcolor(util.GREEN, f"✅ Test Passed: pinRetries = {pin_retries}")





def getPINtokenPubkey(curpin,rp,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,rp,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey  






def getPINtokenPubkey1(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtokens(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    # Step 4: Parse the CBOR response correctly!
    cbor_payload = binascii.unhexlify(hexstring[2:])  # skip 0x33
    decoded = cbor2.loads(cbor_payload)

    if 0x02 not in decoded:
        raise ValueError("pinToken (0x02) not present in getPINToken response")

    pinToken = decoded[0x02]  # this is the raw 32-byte shared secret
    return pinToken



def createGetPINtokens(pinHashenc, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()

    dataCBOR = "A4"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "05" # getPINtoken
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  # later look into this you should be able to use 04
    
    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand



def createGetPINtoken(pinHashenc, key_agreement,rpId,permission):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    rpId_hex         = cbor2.dumps(rpId).hex().upper()
     #(18 decimal  value =55)makeCredential(01), getAssertion(02), credentialManagement(04), largeBlobWrite(10)

    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex
    dataCBOR = dataCBOR + "0A"+ rpId_hex 

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createCBORmakeCreds(clientDataHash, rp, user, pinAuthToken):

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
        }
    ]

    option  = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A7"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand


