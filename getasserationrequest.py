
#
#     pip3 install smartcard
#     pip3 install cbor2
#     pip3 install python-secrets
#     pip3 install cryptography
#######################
import requests, util, secrets, cbor2
import binascii, os, json, base64
import getAsseration
from textwrap import wrap

FIDOconveyance     = "none" ; 
FIDOattachment     = "cross-platform"; 
FIDOverification   = "preferred";
RP_domain          = "localhost"
AuthBeginfidoserverURL = "http://localhost:5001/fidoapi/authenticate/begin"
AuthBompletefidoserverURL = "http://localhost:5001/fidoapi/authenticate/complete"



################
#  The Platform is this Python App and the Authenticator is the Java Card
#  !!! This uses PROTOCOL V2
#
#################################
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



#############
#  [Info]
#    Get the pinToken and the Pubic key
#  result: toke, pubkey
################################
def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","getInfo")


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


################
#
# EXAMPLE what is being made:
#      
#  !!! This uses PROTOCOL V2 
#################################
def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu






#################################################################
#  [Info]
#
#  result: 009000 success
#######################################################################
def makeAssertion(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result


################
#  JavaCard note uses
#      ES256 (ECDSA with SHA-256)
#################################
import credBlob
def authParasing(response):
    print("response",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = getAsseration.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid",credentialId)
    return credentialId

def AuthenticateUser(pin, rp,response):
    credId =authParasing(response)
    #util.printcolor(util.YELLOW,"")
    #util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    #util.printcolor(util.YELLOW,"""Test started: P-1
       # Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""");
    cryptohash = util.sha256(os.urandom(32) )
    
    result =  makeAssertion(pin, cryptohash, rp, credId)
    return result

#failed case 1

def AuthenticateUserRpIdMissing(pin, username,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-1
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is missing, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  rpIdMissing(pin, cryptohash,credId)


def  rpIdMissing(curpin, clientDataHash, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = missingRPID(clientDataHash,  pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def missingRPID(cryptohash, pinAuthToken, credId):
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    # CBOR encoding
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A4"
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case 2

def AuthenticateUserRpIdNotString(pin, username,rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-2
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is NOT of type STRING, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  rpIdNotString(pin, cryptohash,rp,credId)


def  rpIdNotString(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = rpidNotString(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def rpidNotString(cryptohash, pinAuthToken, rp,credId):
    RpEntity = {
        "id": 6775
    }
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(RpEntity).hex().upper()         # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A4"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case 3

def AuthenticateUserclientDataHash(pin, username,rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-3
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is missing, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  clientDataHashMissing(pin, cryptohash,rp,credId)


def  clientDataHashMissing(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = missingclientDataHash(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def missingclientDataHash(cryptohash, pinAuthToken, rp,credId):
    
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()         # 0x01: rpId
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A4"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case 4

def AuthenticateUserclientDataHashNotString(pin, username,rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-4
         Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is NOT of type BYTE ARRAY, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  clientDataHashNotString(pin, cryptohash,rp,credId)


def  clientDataHashNotString(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    clientDataHash={}
    apdu = clientDatahashNotString(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def clientDatahashNotString(cryptohash, pinAuthToken, rp,credId):
  
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu

#failed case 5

def AuthenticateUserallowListNotSet(pin, username,rp,credId):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-5
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" is NOT of type ARRAY, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  allowListNotArray(pin, cryptohash,rp,credId)


def  allowListNotArray(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    apdu = allowListNotOfArray(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def  allowListNotOfArray(cryptohash, pinAuthToken, rp,credId):
  
    allow_list ={}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu

#failed case 6

def AuthenticateUserallowListNotMap(pin, username,rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 1****")
    util.printcolor(util.YELLOW,"""Test started: F-6
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" contains a credential that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  allowListNotMap1(pin, cryptohash,rp,credId)


def  allowListNotMap1(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    apdu = allowListNotTypeofMap(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def  allowListNotTypeofMap(cryptohash, pinAuthToken, rp,credId):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key",
    },"T_HVkk6H4f1YZnab3psl"]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case 7

def AuthenticateUserallowListNotMap1(pin, username,rp,credId):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request****")
    util.printcolor(util.YELLOW,"""Test started: F-6
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" contains a credential that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  allowListNotMap(pin, cryptohash,rp,credId)


def  allowListNotMap(curpin, clientDataHash,rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    apdu = allowListNotTypeofMap(clientDataHash,  pinAuthToken, rp,credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def  allowListNotTypeofMap(cryptohash, pinAuthToken, rp,credId):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key",
    },"T_HVkk6H4f1YZnab3psl"]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu






#pass case2
def AuthenticateUserforOption(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 2****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, "options" containg an unknown option, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  optionUnknown(pin, cryptohash, rp, credId)

def optionUnknown(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeforOptionp(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    if result[0:2] == "34":
        util.printcolor(util.RED, f"\n⚠️ PIN_AUTH_BLOCKED (0x34) detected. Initiating power cycle reset...")
        util.ResetCardPower()
        # Retry one time after power cycle
        util.ConnectJavaCard()
        pinToken, pubkey = getPINtokenPubkey(curpin)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
        apdu = createCBORmakeforOptionp(clientDataHash, rp, pinAuthToken, credId)
        result, status = util.APDUhex(apdu, "GetAssertion Retry", checkflag=True)

    return result

def createCBORmakeforOptionp(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    option={"maketea" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option     = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu

#pass case3
def AuthenticateUserOptionup(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 2****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        If authenticator supports "up" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.up set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UP flag set.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  optionUpSet(pin, cryptohash, rp, response)

def optionUpSet(curpin, clientDataHash, rp, response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    apdu = createCBORmakeOptionU(clientDataHash, rp, pinAuthToken, credId)


    if isinstance(apdu, str):
        result, status =  util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result
    
   

def createCBORmakeOptionU(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

     # Diagnostic print
    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Final payload = 01 prefix + dataCBOR
    full_data = "02" + dataCBOR
    byte_len = len(full_data) // 2
    

    # ========================
    # CASE 1: ≤ 256 → 1 APDU
    # ========================
    if byte_len <= 256:
        lc = format(byte_len, '02X')
        return "80108000" + lc + full_data  # single string

    # ========================
    # CASE 2: > 256 → Chain
    # ========================
    else:
        max_chunk_size = 255 * 2  # 510 hex chars
        chunks = wrap(full_data, max_chunk_size)
        apdus = []

        for i, chunk in enumerate(chunks):
            cla = "90" if i < len(chunks) - 1 else "80"
            ins = "10"
            p1 = "80"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)

        return apdus  # list of chained APDUs

#pass case4
def AuthenticateUserOptionuv(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 2****")
    util.printcolor(util.YELLOW,"""Test started: P-3
        If authenticator supports "uv" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UV flag set.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  optionUvSet(pin, cryptohash, rp, credId)

def optionUvSet(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    
#pass case3
def AuthenticateUserOptionuv1(pin, username, rp,credId):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request****")
    util.printcolor(util.YELLOW,"""Test started: P-3
        If authenticator supports "uv" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UV flag set.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  optionUvSet(pin, cryptohash, rp, credId)

def optionUvSet(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeOptionUv(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    if result[0:2] == "34":
        util.printcolor(util.RED, f"\n⚠️ PIN_AUTH_BLOCKED (0x34) detected. Initiating power cycle reset...")
        util.ResetCardPower()
        # Retry one time after power cycle
        util.ConnectJavaCard()
        pinToken, pubkey = getPINtokenPubkey(curpin)
        pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
        apdu = createCBORmakeOptionUv(clientDataHash, rp, pinAuthToken, credId)
        result, status = util.APDUhex(apdu, "GetAssertion Retry", checkflag=True)

    return result

def createCBORmakeOptionUv(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        "type": "public-key",
        "id": bytes.fromhex(credId)
    }]

    option={"uv" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu




def AuthenticateUserallowListNOTsET(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT set to "public-key", wait for the response, and check that authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptor1(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptor1(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = PublicKeyCredentialDescriptorNotset(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result

def PublicKeyCredentialDescriptorNotset(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id": bytes.fromhex(credId),
         "type": "public-key"
    },
    {"id": bytes.fromhex("E5844A7355954F49E93DA27940C09CCCA77709707302703806F77FBABAF82CE6"),
    "type": "queen-elisabeth-the-second"}]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case
def AuthenticateUserallowListNOTMap(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: F-1
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains an element that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptorNotmap(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptorNotmap(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = PublicKeyCredentialDescriptormap(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


def PublicKeyCredentialDescriptormap(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id": bytes.fromhex(credId),
         "type": "public-key"
    },
    []]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu



#failed case
def PublicKeyCredentialDescriptorType(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: F-2
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is missing, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptor(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptor(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = PublicKeyCredentialDescriptorFieldMissing(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


def PublicKeyCredentialDescriptorFieldMissing(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id": bytes.fromhex(credId),
         "type": "public-key"
    },
    {"id": bytes.fromhex("E5844A7355954F49E93DA27940C09CCCA77709707302703806F77FBABAF82CE6")}]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu





#failed case
def PublicKeyCredentialDescriptorTypeNot(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""TTest started: F-3
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptorNotText(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptorNotText(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = PublicKeyCredentialDescriptorFieldNotText(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


def PublicKeyCredentialDescriptorFieldNotText(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id"  : bytes.fromhex(credId),
        "type": "public-key"
    },
    {"id"   : bytes.fromhex("E5844A7355954F49E93DA27940C09CCCA77709707302703806F77FBABAF82CE6"),
     "type" :[]}]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu




#failed case
def PublicKeyCredentialDescriptorIdMissing(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: F-4
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is missing, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptorIdFiledMissing(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptorIdFiledMissing(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = pcdIdFiledMissing(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


def pcdIdFiledMissing(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id"  : bytes.fromhex(credId),
        "type": "public-key"
    },
    {"type" :"public-key"}]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


#failed case
def PublicKeyCredentialDescriptorIdarray(pin, username, rp,response):
    credId =authParasing(response)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: F-5
        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is NOT of type ARRAY BUFFER, wait for the response, and check that Authenticator returns an error.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  PublicKeyCredentialDescriptorIdNotArray(pin, cryptohash, rp, credId)

def PublicKeyCredentialDescriptorIdNotArray(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = pcdIdNotArrayBuffer(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


def pcdIdNotArrayBuffer(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
       
        "id"  : bytes.fromhex(credId),
        "type": "public-key"
    },
    { "id"  : False,
      "type" :"public-key"}]

    option={"up" :True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu



def PublicKeyCredentialDescriptorallowListMissing(pin, username, rp,response):
    credId =authParasing(response)
    
    util.printcolor(util.YELLOW,"****GetAssertion Request 3****")
    util.printcolor(util.YELLOW,"""Test started: F-6
        If authenticator is Second-Factor only: Send CTAP2 authenticatorGetAssertion(0x02) message, with missing "allowList", and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.""");
    cryptohash = util.sha256(os.urandom(32) )
    result =  allowListMissing(pin, cryptohash, rp, credId)

def allowListMissing(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

   

def DeviceResetProcess():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"**** Reset****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Successfully execute makeCredential, and test it by sending consequent getAssertion and check that both are succeeding.
        Send authenticatorReset(0x07) immidietly after, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with credId from the previously registered makeCredential, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.""");


def residentKey():
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""");


def residentKeyrk():
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        FOR AUTHENTICATORS WITHOUT A DISPLAY AND PERFORM NO VERIFICATION

        Send three valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, and if authenticator supports UV option set "uv" to false, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with no allowList presented, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 3.
        Send authenticatorGetNextAssertion(0x08), until numberOfCredentials is 1, retrieve responses and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for each of the requests. Check that response.user ONLY contains id field and nothing else!""");
   




