import util
import binascii
import cbor2
import hashlib
import util
import Setpinp22
import os
import cbor2
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import clientprotocol1
import clientprotocol2
import changePIN2_2
import DocumentCreation

rp = "localhost"
curPin = "12345678"
newPin = "12345678"
user = "bobsmith"
clientDataHash = os.urandom(32)
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "GET KEY AGREEMENT"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def getKeyAgreement(mode, reset_required, set_pin_required, protocol):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL
    

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
       
"formatCheckKeyAgreement": """Test started: P-1 :
        Send a valid keyAgreement command and verify that the authenticator returns CTAP2_OK. Confirm that the authenticator provides the keyAgreement data in the correct CTAP-specified COSE key format, including the proper key type, algorithm, and all required fields. """,


"checkGeneratedSharedSecret": """Test started: P-2 :
        Send a valid keyAgreement request and ensure the authenticator returns CTAP2_OK along with the keyAgreement. Try to encapsulate the authenticator's public key, ensuring the encapsulation succeeds and a shared secret is generated. """,


"setPINKeyAgreement": """Test started: P-3 :
		Precondition: Authenticator must be reset and has no PIN set.;
        Set a new PIN, ensuring that the keyAgreement (0x02) command is executed with all correct parameters. The authenticator must return CTAP2_OK. """,



"verifyPINKeyAgreement": """Test started: P-4 :
        Verify the newly set PIN, ensuring that the keyAgreement (0x02) command is executed with all correct parameters. The authenticator must return CTAP2_OK.""",



"changePINKeyAgreement": """Test started: P-5 :
        Change the old PIN to new PIN, ensuring that the keyAgreement (0x02) command is executed with all correct parameters. The authenticator must return CTAP2_OK.""",



"missingParameterKeyAgreement": """Test started: P-6 :
		Precondition: Authenticator must be reset and has no PIN set.;
        Attempt to send an invalid keyAgreement command by omitting(missing) a mandatory parameter (subCommand). The authenticator must return CTAP2_ERR_MISSING_PARAMETER.""",


"invalidProtocolKeyAgreement": """Test started: P-7 :
		Precondition: Authenticator must be reset and has no PIN set.;
        Attempt to send an invalid keyAgreement command by providing an unsupported value for a protocol parameter (e.g., pinUvAuthProtocol = 3). The authenticator must return CTAP1_ERR_INVALID_PARAMETER.""",

"invalidSubCommandKeyAgreement": """Test started: P-8 :
		Precondition: Authenticator must be reset and has no PIN set.;
        Attempt to send an invalid keyAgreement command by providing an invalid value for a mandatory parameter (e.g., subCommand = 0x0A). The authenticator must return CTAP2_ERR_INVALID_SUBCOMMAND.""",

"consecutiveKeyAgreement": """Test started: P-9 :
        Send keyAgreement request 10 - 20 times consecutively.  Verify that repeated getKeyAgreement requests do not cause inconsistent or invalid output. Authenticator must return CTAP2_OK and generate a valid public key each time.""",
    
    }

    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    # util.APDUhex("80100000010400", "GetInfo")
    pin = "12345678"

    if reset_required == "yes":
        util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        # util.APDUhex("80100000010400", "GetInfo")

    if set_pin_required == "yes":
        pin = curPin
        if protocol == "PROTOCOL_ONE":
            setpinProtocol1(pin)  #Set new pin 12345678
        elif protocol == "PROTOCOL_TWO":
            setpinProtocol2(pin)  #Set new pin 12345678

    util.APDUhex("80100000010400", "GetInfo")
    old_pin = pin
    subCommand = "02"
    supportedProtocol_ONE = "01"
    supportedProtocol_TWO = "02"
    unSupportedProtocol = "03"
    if protocol == "PROTOCOL_ONE":
        PROTOCOL = 1
    else:
        PROTOCOL = 2
   
    if mode == "formatCheckKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            cardPublickey, status = keyAgreementCMD(supportedProtocol_ONE, subCommand, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
                checkCOSEKeyFormat(cardPublickey)  
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        elif protocol == "PROTOCOL_TWO":
            cardPublickey, status= keyAgreementCMD(supportedProtocol_TWO, subCommand, mode)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
                checkCOSEKeyFormat(cardPublickey)  
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "checkGeneratedSharedSecret":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            keyAgreement, shareSecretKey = keyAgreementWithSharedSecretProtocol1(supportedProtocol_ONE, subCommand, mode)
            util.printcolor(util.YELLOW, "Public Key Encapsulated and Shared Secret Generated Successfully")
            shareSec = util.toHex(shareSecretKey)
            util.printcolor(util.BLUE, f"Generated Shared Secret -> {shareSec}")
        elif protocol == "PROTOCOL_TWO":
            keyAgreement, shareSecretKey = keyAgreementWithSharedSecretProtocol2(supportedProtocol_TWO, subCommand, mode)
            util.printcolor(util.YELLOW, "Public Key Encapsulated and Shared Secret Generated Successfully")
            shareSec = util.toHex(shareSecretKey)
            util.printcolor(util.BLUE, f"Generated Shared Secret -> {shareSec}")
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
        

    elif mode == "setPINKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            response, status = setpinProtocol1(curPin)  #Set new pin 12345678
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        elif protocol == "PROTOCOL_TWO":
            response, status = setpinProtocol2(curPin)  #Set new pin 12345678
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "verifyPINKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            response, status = changePIN2_2.makeCredProtocol1(curPin, clientDataHash, rp, user)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)

        elif protocol == "PROTOCOL_TWO":
            response, status = changePIN2_2.makeCredProtocol2(curPin, clientDataHash, rp, user)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
    
    elif mode == "changePINKeyAgreement":
        scenarioCount += 1
        new_pin = "12345678"
        if protocol == "PROTOCOL_ONE":
            response, status = changePIN2_2.changePINProtocol1(curPin, new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
            
        elif protocol == "PROTOCOL_TWO":
            response, status = changePIN2_2.changePINProtocol2(curPin, new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)

        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "missingParameterKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            cardPublickey, status= keyAgreementCMD(supportedProtocol_ONE, subCommand, mode) 
            if status == "14":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_ERR_MISSING_PARAMETER")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
            
        elif protocol == "PROTOCOL_TWO":
            cardPublickey, status= keyAgreementCMD(supportedProtocol_TWO, subCommand, mode) 
            if status == "14":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_ERR_MISSING_PARAMETER")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1
                 

    elif mode == "invalidProtocolKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            cardPublickey, status= keyAgreementCMD(unSupportedProtocol, subCommand, mode) 
            if status == "02":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP1_ERR_INVALID_PARAMETER")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
            
        elif protocol == "PROTOCOL_TWO":
            cardPublickey, status= keyAgreementCMD(unSupportedProtocol, subCommand, mode) 
            if status == "02":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP1_ERR_INVALID_PARAMETER")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)

        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "invalidSubCommandKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            cardPublickey, status= keyAgreementCMD(supportedProtocol_ONE, "0A", mode) 
            if status == "3E":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_ERR_INVALID_SUBCOMMAND")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)
            
        elif protocol == "PROTOCOL_TWO":
            cardPublickey, status= keyAgreementCMD(supportedProtocol_TWO, "0A", mode) 
            if status == "3E":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_ERR_INVALID_SUBCOMMAND")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                failCount += 1
                exit(0)

        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "consecutiveKeyAgreement":
        scenarioCount += 1
        if protocol == "PROTOCOL_ONE":
            for x in range(10):
                util.printcolor(util.YELLOW,f"PERFORMING KEY AGREEMENT - {x+1} TIME")
                cardPublickey, status= keyAgreementCMD(supportedProtocol_ONE, subCommand, mode) 
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                    failCount += 1
                    exit(0)

                checkCOSEKeyFormat(cardPublickey)
        elif protocol == "PROTOCOL_TWO":
            for y in range(10):
                util.printcolor(util.YELLOW,f"PERFORMING KEY AGREEMENT - {y+1} TIME")
                cardPublickey, status= keyAgreementCMD(supportedProtocol_TWO, subCommand, mode) 
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}' - CTAP2_OK")
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                    failCount += 1
                    exit(0)
                checkCOSEKeyFormat(cardPublickey)

        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1



def checkCOSEKeyFormat(resp_hex):

    # Convert from hex → bytes
    resp = bytes.fromhex(resp_hex)

    # 1. Extract CTAP status code (first byte)
    status = resp[0]
    cbor_payload = resp[1:]  # remaining bytes

    print("CTAP Status Code:", hex(status))
    if status != 0x00:
        raise ValueError("Authenticator did not return CTAP2_OK")

    # 2. Decode CBOR
    decoded = cbor2.loads(cbor_payload)
    util.printcolor(util.BLUE,f"Decoded CBOR: {decoded}")

    # 3. Extract keyAgreement structure
    key_agreement = decoded.get(0x01)  # field "1" → keyAgreement

    if not key_agreement:
        raise ValueError("Missing keyAgreement field in response")

    util.printcolor(util.BLUE,f"\nkeyAgreement structure:  {key_agreement}")

    # 4. Validate required COSE key fields for ECDH (P-256)
    required_fields = {
    1: "kty",   # Key Type
    3: "alg",   # Algorithm
   -1: "crv",   # Curve
   -2: "x",     # X-coordinate
   -3: "y",     # Y-coordinate
    }

    missing = []
    for field in required_fields:
        if field not in key_agreement:
            missing.append(required_fields[field])

    if missing:
        raise ValueError(f"Missing COSE fields: {missing}")

    util.printcolor(util.YELLOW,"\nAll required COSE fields are present.")

    # 5. Additional correctness checks
    if key_agreement[1] != 2:
        raise ValueError("Invalid kty: expected 2 (EC2)")

    if key_agreement[3] not in [-25, -257]:
        util.printcolor(util.RED,"Warning: alg is unusual (expected -25 = ECDH-ES-HKDF-256)")

    if key_agreement[-1] != 1:
        raise ValueError("Invalid crv: expected 1 (P-256)")

    util.printcolor(util.GREEN,"COSE key format looks correct!")






def verifyPIN(curpin, rp, user):
    util.printcolor(util.YELLOW, "")
    # ------------------------------
    #   TEST DESCRIPTIONS
    # ------------------------------

    # ------------------------------
    #   SELECT + GETINFO
    # ------------------------------
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   COMMON FIELDS
    # ------------------------------
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkeyTemp(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    # ------------------------------
    #   RP FEILD
    # ------------------------------
    rp_entity = {"id": rp, "name": rp}
    # ------------------------------
    #   USER FEILD
    # ------------------------------
    user_entity = {
        "id": user.encode(),
        "name": user,
        "displayName": user
    }
    # ----------------------------------------------------
    #        pubKeyCredParams 
    # ----------------------------------------------------
    pubKeyCredParams = [
            {"alg": -7, "type": "public-key"}
        ]

    makeCredAPDU = build_make_cred_apdu(
        clientDataHash,
        rp_entity,
        user_entity,
        pubKeyCredParams,
        pubkey,
        pinAuthToken)
    

    # ----------------------------------------------------
    #   SEND APDU (single or chained)
    # ----------------------------------------------------
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, f"Client PIN command as subcmd 0x01 make Credential: ", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                "Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status



# =================================================================
#    UPDATED build_make_cred_apdu()  (INCLUDES excludeList)
# =================================================================

def build_make_cred_apdu(clientDataHash, rp_entity, user_entity,
                         pubKeyCredParams,  pubkey, pinAuthToken):

    options = {"rk": True}

    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # CBOR MAP (A8 = 8 entries)
    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"

    finalPayload = "01" + dataCBOR
    payload = bytes.fromhex(finalPayload)

    # Single APDU
    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80108000" + lc + finalPayload

    # Chained APDU
    return util.build_chained_apdus(payload)

def getPINtokenPubkeyTemp(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey

def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    #print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def createGetPINtoken(pinHashenc, key_agreement):
    
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



def changePINOnly(old_pin, new_pin):
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

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
    return  response, status 



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


def keyAgreementWithSharedSecretProtocol1(pinUvAuthProtocol, subCommand, mode):
    apdu = "801080000606a201" + pinUvAuthProtocol + "02" + subCommand + "00"
    cardPublickey, status= util.APDUhex(apdu,"Client PIN subcmd 0x02 getKeyAgreement",True)
    if status == "00":
        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR KEY AGREEMENT (PROTOCOL - 1) : '{status}' - CTAP2_OK")
    else:
        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR KEY AGREEMENT (PROTOCOL - 1) : '{status}'")
        exit(0)
    
    cbor_bytes = binascii.unhexlify(cardPublickey[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = encapsulate_protocol1(decoded[1])

    return key_agreement, shared_secret


def keyAgreementWithSharedSecretProtocol2(pinUvAuthProtocol, subCommand, mode):
    apdu = "801080000606a201" + pinUvAuthProtocol + "02" + subCommand + "00"
    cardPublickey, status= util.APDUhex(apdu,"Client PIN subcmd 0x02 getKeyAgreement",True)
    if status == "00":
        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR KEY AGREEMENT (PROTOCOL - 2) : '{status}' - CTAP2_OK")
    else:
        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR KEY AGREEMENT (PROTOCOL - 2) : '{status}'")
        exit(0)

    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = encapsulate_protocol2(decoded_data[1])

    return key_agreement, shareSecretKey


def encapsulate_protocol2(peer_cose_key):
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

def setpinProtocol1(pin):
    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = encapsulate_protocol1(decoded[1])
    padded_pin = pad_pin(pin, validate=False)  # skips min length check
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = hmac_sha256(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response , status


def encapsulate_protocol1(peer_cose_key):
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

def setpinProtocol2(pin):
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    response , status  = util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response, status


def createCBOR(newPINenc, auth, key_agreement):
        platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
        cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
        cbor_auth        = cbor2.dumps(auth).hex().upper()
        dataCBOR = "A5"
        dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
        dataCBOR = dataCBOR + "02"+ "03" # setPIN
        dataCBOR = dataCBOR + "03"+ platformCOSKEY
        dataCBOR = dataCBOR + "04"+ cbor_auth
        dataCBOR = dataCBOR + "05"+ cbor_newPINenc
        length = (len(dataCBOR) >> 1) +1     #have to add the 06

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand 


def keyAgreementCMD(pinUvAuthProtocol, subCommand, mode):
    if mode == "missingParameterKeyAgreement":
        apdu = "801080000406a101" + pinUvAuthProtocol + "00"
    else:
        apdu = "801080000606a201" + pinUvAuthProtocol + "02" + subCommand + "00"
    
    cardPublickey, status= util.APDUhex(apdu,"Client PIN subcmd 0x02 getKeyAgreement",True)
    return cardPublickey, status


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

def bytes2int(value: bytes) -> int:
    """Parses an arbitrarily sized integer from a byte string.

    :param value: A byte string encoding a big endian unsigned integer.
    :return: The parsed int.
    """
    return int.from_bytes(value, "big")

def pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    # if validate:
    #     if len(pin_bytes) < 6:
    #         raise ValueError("PIN must be at least 6 bytes")
    #     if len(pin_bytes) > 64:
    #         raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()

    data_cbor = "A5"
    data_cbor += "01" + "01"            # pinProtocol = 1
    data_cbor += "02" + "03"            # subCommand = 3 (SetPIN)
    data_cbor += "03" + cose_key        # keyAgreement
    data_cbor += "04" + cbor_auth       # pinAuth
    data_cbor += "05" + cbor_newpin     # newPinEnc

    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor
    return apdu

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()