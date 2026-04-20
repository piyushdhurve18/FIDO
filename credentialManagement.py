import cbor2
import util
import binascii
import clientprotocol2
import make_credential_request
import hmac
import hashlib
import os
import getAsseration
import getasserationrequest
from textwrap import wrap
import time


import cbor2

def createCredential(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create new discoverable credential. Send authenticatorCredentialManagement(0x0A) with getCredsMetadata(0x01), and check that existingResidentCredentialsCount is 1, and maxPossibleRemainingResidentCredentialsCount is more than 1.
        Create another discoverable credential, and make sure that existingResidentCredentialsCount is now 2.""")
    getCredsMetadata(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="sasmita"
    hashchallenge = os.urandom(32);
    RP_domain="goggle.com"
    getCredsMetadata("123456",hashchallenge,RP_domain,user)



def createCredentialManagemetrp(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that result:
            (a) Result.rp is present and of type MAP
            (b) Result.rp.id is present and is of type String.
            (c) Result.rp.id is in a list of known rpIDs.
            (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.
            (e) Result.totalRPs is a Number and is set to 2, same as a number of registered RPIDs.""")
    enumerateRPsBegin(pin, clientDataHash, rp, user)



def credentialmgntEnumerateRPsGetNextRP():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-3

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsGetNextRP(0x03), and check that result:
            (a) Result.rp is present and of type MAP
            (b) Result.rp.id is present and is of type String.
            (c) Result.rp.id is in a list of known rpIDs.
            (d) Result.rpIDHash is a valid SHA-256 hash of Result.rp.id, and is of type BYTESTRING.""")
    enumerateRPsGetNextRP()

def enumerateCredentialsBegin(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsBegin(0x04), and make sure that:
            (a) Response.credentialID is of type PublicKeyCredentialDescriptor, and matching previously recorded credentialID
            (b) Response.user is of type PublicKeyCredentialUserEntity, and at least contains id, that matches previously recorded
            (c) Response.publicKey is a COSE_Key and matches previously recorded
            (d) Response.totalCredentials is a number and set to 2, same as registered credentials.""")
    credential_data(pin, clientDataHash, rp, user)





def enumerateCredentialsGetNextCredential():
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsGetNextCredential(0x05), and make sure that:
            (a) Response.credentialID is of type PublicKeyCredentialDescriptor, and matching previously recorded credentialID
            (b) Response.user is of type PublicKeyCredentialUserEntity, and at least contains id, that matches previously recorded
            (c) Response.publicKey is a COSE_Key and matches previously recorded
            (d) Response.totalCredentials is undefined.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000040aa1010500", "enumerateCredentialsGetNextCredential(0x05)")

def updateUserInformation(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
            (a) At least Response.user.id is present and matches new value.
            (b) If authenticator supports name and displayName fields, make sure that updated value is correct and missing field is now removed.""")
    updateCredentialdata(pin, clientDataHash, rp, user)


def deleteCredential(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), and check that authenticator succeds. Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""")
    deleteCredentialdata(pin, clientDataHash, rp, user)

def deleteCredentialdata(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu = deleteCredInfo(pinToken, subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    #check credential is there or not
    getasserationrequest.makeAssertion(pin, clientDataHash, rp, credId)

def extractCBORMap(response):
    if len(response) > 6:
        result = response[2:]
    else:
        result = ""
    return result

def getCredCountsInteger(response):
    cborData = extractCBORMap(response)
    print("cborData => ",cborData)
    data = bytes.fromhex(cborData)
    decoded = cbor2.loads(data)

    # Ensure CBOR is a map
    if not isinstance(decoded, dict):
        raise TypeError(f"Expected CBOR map, got {type(decoded).__name__}")

    existingResidentCredentialsCount = decoded.get(1)
    maxPossibleRemainingResidentCredentialsCount = decoded.get(2)

    # Ensure integer output
    if existingResidentCredentialsCount is not None:
        existingResidentCredentialsCount = int(existingResidentCredentialsCount)

    if maxPossibleRemainingResidentCredentialsCount is not None:
        maxPossibleRemainingResidentCredentialsCount = int(maxPossibleRemainingResidentCredentialsCount)

    return existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount


def deleteCredentialdataProtocol2(pin, clientDataHash, rp, user):
   
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.printcolor(util.YELLOW,f"Duplicate Make Cred Client Data Hash for Delete Cred -> {util.toHex(clientDataHash)}")
    util.printcolor(util.YELLOW,f"Duplicate Make Cred RP Id for Delete Cred -> {rp}")
    util.printcolor(util.YELLOW,f"Duplicate Make Cred User for Delete Cred -> {user}")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.printcolor(util.BLUE,f"DUPLICATE CREDENTIAL CREATED SUCCESSFULLY FOR AUTH PARSING !!!")
    response1, status1 = getCredsMetadataTemp(pin, clientDataHash, rp, user)
    if status1 == "00":
        util.printcolor(util.GREEN,f"GET CRED META DATA WITH STATUS CODE: {status1}")
    else:
        util.printcolor(util.RED,f"GET CRED META DATA FAILED WITH STATUS CODE: {status1}")
    credId =getasserationrequest.authParasing(response)

    
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)

    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    #check credential is there or not
    getasserationrequest.makeAssertion(pin, clientDataHash, rp, credId)
    return response, status

def deleteCredentialdataWithMakeCredResponseProtocol2(pin, clientDataHash, rp, user, response):
   
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    # response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    util.printcolor(util.YELLOW,f"Client Data Hash for Delete Cred -> {util.toHex(clientDataHash)}")
    util.printcolor(util.YELLOW,f"RP Id for Delete Cred -> {rp}")
    util.printcolor(util.YELLOW,f"User for Delete Cred -> {user}")
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"DELETE CREDENTIAL FAILED : {status}")
        exit(0)
    #check credential is there or not
    getasserationrequest.makeAssertion(pin, clientDataHash, rp, credId)
    return response, status


def deleteCredentialdataProtocol1(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredProtocol1(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
    #check credential is there or not
    getasserationrequest.makeAssertion(pin, clientDataHash, rp, credId)



def updateCredentialdata(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=updateUserInfo(pinToken,subCommand,user,credId) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
    #after we checking the authenticatorCredentialManagement data
    
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    
    apdu = enumerateCredentials(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)




def updateUserInfo(pinToken,subCommand,user,credential_id):
    #updated only user name and display name

    updated_user_entity= {
                "id": user.encode(), # id: byte sequence
                "name": "bobsmith_updated",  # name 
                "displayName": "Bob Smith Updated",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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



def deleteCredInfo(pinToken,subCommand,credential_id):
    
    #delete credential
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        }
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    #util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu



   
    


def enumerateRPsGetNextRP():
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000040aa1010300","enumerateRPsGetNextRP(0x03)")


def enumerateRPsBegin(pin, clientDataHash, rp, user):
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x02  # enumerateRPsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)





def getCredsMetadata(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    # make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)

    
def getCredsMetadataTemp(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    # make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)
    data = bytes.fromhex(response)
    resLength = len(data)
    if resLength > 3:
        existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount = getCredCountsInteger(response)
        util.printcolor(util.YELLOW,f"existingResidentCredentialsCount = {existingResidentCredentialsCount}")
        util.printcolor(util.YELLOW,f"maxPossibleRemainingResidentCredentialsCount = {maxPossibleRemainingResidentCredentialsCount}")

    return response, status
    

def credential_data(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="bobsmith"
    clientDataHash = os.urandom(32);
    RP_domain="entra.com"
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    
    apdu = enumerateCredentials(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)






def enumerateCredentials(subCommand, pinToken,rp):
    rpIDHash = hashlib.sha256(rp.encode('utf-8')).digest()
    subCommandParams = {
        0x01: rpIDHash
    }
# message = subCommand || CBOR(subCommandParams)
    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    message = bytes([subCommand]) + subCommandParamsBytes
    pinUvAuthParam = hmac.new( pinToken, message, digestmod='sha256').digest()[:32]

    # Step 5: Final CBOR map
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu

def emptyUserName(pinToken,subCommand,user,credential_id):
    #updated only user name and display name

    updated_user_entity= {
                "id": user.encode(), # id: byte sequence
                "name": "bobsmith_updated",  # name 
                "displayName": "Bob Smith Updated",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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




































def getCredsMetadata_APDU(subCommand, pinUvAuthParam):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2,                   # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam       # HMAC-SHA256(pinToken, [subCommand])[:16]
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    #util.printcolor(util.BLUE, cbor_hex)
    #util.hex_string_to_cbor_diagnostic(cbor_hex)
    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu


def missingpinauthgetCredsMetadata_APDU(subCommand):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2                  # pinUvAuthProtocol = 2
        
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    util.printcolor(util.BLUE, cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)
    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu



def getCredsMetadata_APDU_minimal(subCommand):
    cbor_map = {
        0x01: subCommand,
        0x03: 0x02
    }
    final_cbor = cbor2.dumps(cbor_map)
    util.printcolor(util.BLUE, final_cbor.hex().upper())
    util.hex_string_to_cbor_diagnostic(final_cbor.hex())

    length = len(final_cbor) + 1
    APDUcommand = "80108000" + format(length, '02X') + "0A" + final_cbor.hex().upper()
    return APDUcommand

def getPINtokenPubkey(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)

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

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def getPINtokenPubkey1(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def createGetPINtoken(pinHashenc, key_agreement,permission):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


####################extra test case################################
def updateCredentialEmpty(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=updateUserInfo(pinToken,subCommand,user,credId) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)




def emptyUserName(pinToken,subCommand,user,credential_id):
    #updated only user name and display name

    updated_user_entity= {
                "id": user.encode(), # id: byte sequence
                "name": "bobsmith_updated",  # name 
                "displayName": "Bob Smith Updated",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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
    


#extra usercredential case
def updateInformationEmptyUser(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserName field is empty.""")
    emptyUserName(pin, clientDataHash, rp, user)


def emptyUserName(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userNameisEmpty(pinToken,subCommand,user,credId) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
   



def userNameisEmpty(pinToken,subCommand,user,credential_id):
    #updated only user name and display name

    updated_user_entity= {
                "id": user.encode(), # id: byte sequence
                "name": "",  # empty userName 
                "displayName": "Bob Smith Updated",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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
    
#case 2
def updateuserName4byte(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserName field is 4 byte .""")
    
    displayName(pin, clientDataHash, rp, user)

def updateuserName18byte(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserName field is 18 byte .""")
    displayName(pin, clientDataHash, rp, user)


def updateuserName50byte(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserName field is 50 byte .""")
    response=updatedUserName(pin, clientDataHash, rp, user)
    return response

def updateuserName100byte(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserName field is 100 byte .""")
    response=updatedUserName(pin, clientDataHash, rp, user)
    return response


def displayName(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)

    subCommand = 0x07 
    apdu=userNameis10(pinToken,subCommand,user,credId) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def updatedUserName(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userNameis10(pinToken,subCommand,user,credId) 
    #response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
    if isinstance(apdu, str):
        result, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result



def userNameis10(pinToken,subCommand,user,credential_id):
    #updated only user name and display name
   
    updated_user_entity= {
                "id":user.encode(), # id: byte sequence
                "name": user,  # empty userName 
                "displayName": "Bob Smith Updated",  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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
    

def updatedisplayName4byte(pin, clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserDisplayName field is 4 byte .""")
    
    displayName(pin, clientDataHash, rp, user,userdisplay)

def updatedisplayName18byte(pin, clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserDisplayName field is 18 byte .""")
    
    displayName(pin, clientDataHash, rp, user,userdisplay)

def updatedisplayName50byte(pin, clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserDisplayName field is 50 byte .""")
    
    displayName(pin, clientDataHash, rp, user,userdisplay)

def updatedisplayName100byte(pin, clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserDisplayName field is 100 byte .""")
    
    displayNameUpdated(pin, clientDataHash, rp, user,userdisplay)

def updatedisplayNameEmptybyte(pin, clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the UserDisplayName field is Empty byte .""")
    
    displayName(pin, clientDataHash, rp, user,userdisplay)


def wrongUserId(pin, clientDataHash, rp, user,userid):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          Verify that the Userid is wrong .""")
    
    wronguserID(pin, clientDataHash, rp, user,userid)



def wrongCredId(pin, clientDataHash, rp, user,userid):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create a discoverable credential. Send authenticatorCredentialManagement(0x0D) with updateUserInformation(0x07), and make sure that:
          If no matching credential is found, return CTAP2_ERR_NO_CREDENTIALS.""")
    
    wrongcredID(pin, clientDataHash, rp, user,userid)

#pinauthbased
def CMpermission(pin,clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        P-RPID cm permission;the RP ID of the credential.""")
    validCMpermission(pin,clientDataHash, rp, user,userdisplay)
def wrongCMpermission(pin,clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        RPID wrong cm permission;the RP ID of the credential return CTAP2_ERR_PIN_AUTH_INVALID(33).""")
    CMpermissionwrong(pin,clientDataHash, rp, user,userdisplay)
def noCMpermission(pin,clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: 

        RPID no cm permission;the RP ID of the credential return CTAP2_ERR_PIN_AUTH_INVALID(33).""")
    noCMper(pin,clientDataHash, rp, user,userdisplay)


def notVaildRPid(pin,clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: 

        RPID no cm permission;the RP ID of the credential return CTAP2_ERR_PIN_AUTH_INVALID(33).""")
    CMpermissionwrong(pin,clientDataHash, rp, user,userdisplay)

def pinauthMissing(pin,clientDataHash, rp, user,userdisplay):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        F-If pinUvAuthParam is missing from the input map, end the operation by returning CTAP2_ERR_PUAT_REQUIRED(36).""")
    missingPinAuth(pin,clientDataHash, rp, user,userdisplay)
def validCMpermission(pin, clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userdisplay10(pinToken,subCommand,user,credId,userdisplay) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def CMpermissionwrong(pin,clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    permission = 0x04  # wrong Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userdisplay10(pinToken,subCommand,user,credId,userdisplay) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
def missingPinAuth(pin,clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    permission = 0x04  # wrong Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=pinauthSupport(subCommand,user,credId,userdisplay) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def noCMper(pin,clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    pinToken, pubkey = make_credential_request. getPINtokenPubkey(pin)
    subCommand = 0x07 
    apdu=userdisplay10(pinToken,subCommand,user,credId,userdisplay) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)


def displayNameUpdated(pin, clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userdisplay10(pinToken,subCommand,user,credId,userdisplay) 
    if isinstance(apdu, str):
        result, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result


def displayName(pin, clientDataHash, rp, user,userdisplay):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=userdisplay10(pinToken,subCommand,user,credId,userdisplay) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def userdisplay10(pinToken,subCommand,user,credential_id,userdisplay):
    #updated only user name and display name
   
    updated_user_entity= {
                "id":user.encode(), # id: byte sequence
                "name": user,  # empty userName 
                "displayName": userdisplay,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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



def pinauthSupport(subCommand,user,credential_id,userdisplay):
    #updated only user name and display name
   
    updated_user_entity= {
                "id":user.encode(), # id: byte sequence
                "name": user,  # empty userName 
                "displayName": userdisplay,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    
   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2  # pinUvAuthProtocol = 2
       
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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
    


def wronguserID(pin, clientDataHash, rp, user,userid):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    apdu=wrongData(pinToken,subCommand,user,credId,userid) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def wrongcredID(pin, clientDataHash, rp, user,userid):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    response = make_credential_request.makeCred(pin, clientDataHash, rp, user)

    credId =getasserationrequest.authParasing(response)
    credId="01"+credId

    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x07 
    userid=user
    apdu=wrongData(pinToken,subCommand,user,credId,userid) 
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): updateUserInformation(0x07)", checkflag=True)

def wrongData(pinToken,subCommand,user,credential_id,userid):
    #updated only user name and display name
   
    updated_user_entity= {
                "id":userid.encode(), # id: byte sequence
                "name": user,  # empty userName 
                "displayName":"mathewwade" ,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        },
        0x03: updated_user_entity
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
    pinUvAuthParam = hmac.new(pinToken, auth_message, hashlib.sha256).digest()[:32]

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,  # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)



    # Final payload = 01 prefix + dataCBOR
    full_data = "0A" + cbor_hex
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
#extra taest case
def deleteCredential1(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), and check that authenticator succeds. Send subsequent GetAssertion request with deleted credential credID specified in allow list and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E).""")
    deleteCredentialdata1(pin, clientDataHash, rp, user)



def wrongCred(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), wrong Credential id CTAP2_ERR_NO_CREDENTIALS(2E).""")
    notMatchingCredID(pin, clientDataHash, rp, user)



def validCMpermission1(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), providing correct CM permission.""")
    deleteCredentialdata1(pin, clientDataHash, rp, user)


def noCMpermission1(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), no CM permission.""")
    CMperNotProvide(pin, clientDataHash, rp, user)
def wrongCMper(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), not providing correct CM permission.""")
    CMperwrong(pin, clientDataHash, rp, user)


def wrongPinAuth(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0D) with deleteCredential(0x06), If pinUvAuthParam is missing from the input map, end the operation by returning CTAP2_ERR_PUAT_REQUIRED..""")
    pinAuth(pin, clientDataHash, rp, user)

def pinAuth(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredential(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x04
    pinToken, pubkey = make_credential_request.getPINtokenPubkey(pin)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredPinAuthMissing(subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)





def CMperwrong(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredential(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x03
    pinToken, pubkey = make_credential_request.getPINtokenPubkey(pin)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)


def CMperNotProvide(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredential(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    pinToken, pubkey = make_credential_request.getPINtokenPubkey(pin)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)
def notMatchingCredID(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredential(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    credId="01"+ credId
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)

def deleteCredentialdata1(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    response = make_credential_request.makeCredential(pin, clientDataHash, rp, user)
    credId =getasserationrequest.authParasing(response)
    
    permission = 0x04  # Credential Management
    pinToken, pubkey = getPINtokenPubkey(pin, permission)
    subCommand = 0x06  #delecredential credential 
    apdu=deleteCredInfo(pinToken,subCommand, credId)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A):  deleteCredential(0x06)", checkflag=True)



def deleteCredPinAuthMissing(subCommand,credential_id):
    
    #delete credential
    subCommandParams = {
        0x02: {  # credentialId descriptor
            "id": bytes.fromhex(credential_id),
            "type": "public-key"
            
        }
    }
    # Compute pinUvAuthParam
    cbor_params = cbor2.dumps(subCommandParams)
    auth_message = bytes([subCommand]) + cbor_params
   

   
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2  # pinUvAuthProtocol = 2
      
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu


#extratest case  
def getmetadata(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create new discoverable credential. Send authenticatorCredentialManagement(0x0A) with getCredsMetadata(0x01), and check that existingResidentCredentialsCount is 2 not providing the CM persion.""")
    getCredsMetadata(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="sasmita"
    hashchallenge = os.urandom(32);
    RP_domain="goggle.com"
    getCredsMetadatanocmper("123456",hashchallenge,RP_domain,user)

def getCredsMetadatanocmper(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    pinToken, pubkey =make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)


def wrongcmgetmetadata(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create new discoverable credential. Send authenticatorCredentialManagement(0x0A) with getCredsMetadata(0x01), and check that existingResidentCredentialsCount is 2  providing the wrong CM persion.""")
    getCredsMetadata(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="sasmita"
    hashchallenge = os.urandom(32);
    RP_domain="goggle.com"
    getCredsWrongcm("123456",hashchallenge,RP_domain,user)

def getCredsWrongcm(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission=0x03 #wrong cm permission
    pinToken, pubkey =getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)



def wrongPinauthdata(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create new discoverable credential. Send authenticatorCredentialManagement(0x0A) with getCredsMetadata(0x01), and check that existingResidentCredentialsCount is 2  providing the  CM persion with invalid pinauth.""")
    getCredsMetadata(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="sasmita"
    hashchallenge = os.urandom(32);
    RP_domain="goggle.com"
    pinauthWrong("123456",hashchallenge,RP_domain,user)

def pinauthWrong(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission=0x04 #wrong cm permission
    pinToken, pubkey =getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16] #wrong pinauth
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)



def pinauthIsMissing(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create new discoverable credential. Send authenticatorCredentialManagement(0x0A) with getCredsMetadata(0x01), and check that existingResidentCredentialsCount is 2  providing the  CM persion with no pinauthparam.""")
    getCredsMetadata(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="sasmita"
    hashchallenge = os.urandom(32);
    RP_domain="goggle.com"
    missingPinauth("123456",hashchallenge,RP_domain,user)


def missingPinauth(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission=0x04 #wrong cm permission
    pinToken, pubkey =getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x01  # getCredsMetadata
    apdu = missingpinauthgetCredsMetadata_APDU(subCommand)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): getCredsMetadata (subCommand 0x01)", checkflag=True)

#0x04
def enumerateCreBeginWrongcm(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsBegin(0x04), and make sure that:
    Providing wrong CM permission.""")
    cmWorngPer(pin, clientDataHash, rp, user)

def cmWorngPer(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="bobsmith"
    clientDataHash = os.urandom(32);
    RP_domain="entra.com"
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    
    permission = 3  #wrong  CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    
    apdu = enumerateCredentials(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)


def enumerateCreBeginMissingcm(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsBegin(0x04), and make sure that:
   Not  Providing CM permission getting pinauthinvaild(0x33).""")
    cmPerNotAvailable(pin, clientDataHash, rp, user)


def cmPerNotAvailable(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="bobsmith"
    clientDataHash = os.urandom(32);
    RP_domain="entra.com"
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    pinToken, pubkey = make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    
    apdu = enumerateCredentials(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)


def enumerateCreBeginwrongpinauth(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsBegin(0x04), and make sure that:
   CM permission with pinauthparam getting pinauthinvaild(0x33).""")
    cmPerWrongPinauth(pin, clientDataHash, rp, user)

def cmPerWrongPinauth(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="bobsmith"
    clientDataHash = os.urandom(32);
    RP_domain="entra.com"
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission=0x04
    pinToken, pubkey = getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]#wrong pinauth
    apdu = enumerateCredwrongpiauth(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)

def enumerateCreBeginmissingpinauth(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-1

        If authenticator supports Credential Management API: Create two new discoverable credentials. Send authenticatorCredentialManagement(0x0D) with enumerateCredentialsBegin(0x04), and make sure that:
    Providing CM permission with missing pinauthParam getting CTAP2_ERR_PUAT_REQUIRED(0x36).""")
    pinauthIsmissing(pin, clientDataHash, rp, user)

def pinauthIsmissing(pin, clientDataHash, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "get info")
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    util.ResetCardPower()
    util.ConnectJavaCard()
    user="bobsmith"
    clientDataHash = os.urandom(32);
    RP_domain="entra.com"
    make_credential_request.makeCred(pin, clientDataHash, rp, user)
    permission=0x04
    pinToken, pubkey = getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
   
    apdu = enumerateCredpiauthMissing(subCommand,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)


def enumerateCredwrongpiauth(subCommand, pinToken,rp):
    rpIDHash = hashlib.sha256(rp.encode('utf-8')).digest()
    subCommandParams = {
        0x01: rpIDHash
    }
# message = subCommand || CBOR(subCommandParams)
    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    message = bytes([subCommand]) + subCommandParamsBytes
    pinUvAuthParam = hmac.new( pinToken, message, digestmod='sha256').digest()[:16] #wrongpinauth

    # Step 5: Final CBOR map
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2,
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu



def enumerateCredpiauthMissing(subCommand,rp):
    rpIDHash = hashlib.sha256(rp.encode('utf-8')).digest()
    subCommandParams = {
        0x01: rpIDHash
    }
# message = subCommand || CBOR(subCommandParams)
    subCommandParamsBytes = cbor2.dumps(subCommandParams)
    message = bytes([subCommand]) + subCommandParamsBytes
    
    # Step 5: Final CBOR map
    cbor_map = {
        0x01: subCommand,
        0x02: subCommandParams,
        0x03: 2
       
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1  # +1 for CTAP command (0x0A)

    util.printcolor(util.BLUE, "CBOR HEX: " + cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)

    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu




def rpwithwrongcm(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: F-1:

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that CredentialManagement permission is not valid .""")
    enumerateRPsBegin1(pin, clientDataHash, rp, user)
def enumerateRPsBegin1(pin, clientDataHash, rp, user):
    permission = 3  # wrong CredentialManagement permission
    pinToken, pubkey = getPINtokenPubkey1(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x02  # enumerateRPsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)

def rpwithnocm(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: F-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that CredentialManagement permission is absent .""")
    enumerateRPcmabsent(pin, clientDataHash, rp, user)
def enumerateRPcmabsent(pin, clientDataHash, rp, user):
    pinToken, pubkey = make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x02  # enumerateRPsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)



def rpwithwrongpinauth(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that CredentialManagement permission with invalid pinauthparam getting pinauth invaild(ox33) .""")
    wrongpinauth(pin, clientDataHash, rp, user)
def wrongpinauth(pin, clientDataHash, rp, user):
    permission = 4 
    pinToken, pubkey = getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x02  # enumerateRPsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:32]
    pinUvAuthParam=bytes.fromhex("616D65697961686F6F2E636F6D045820B33960790A6DE22CA95A61")
    apdu = getCredsMetadata_APDU(subCommand, pinUvAuthParam)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)



def rpwithmisspinauth(pin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, "**** Credential Management API ****")
    util.printcolor(util.YELLOW, """Test started: P-2

        If authenticator supports Credential Management API: Send authenticatorCredentialManagement(0x0A) with enumerateRPsBegin(0x02), and check that CredentialManagement permission with missing pinauthparam getting pinauth requried(ox36) .""")
    misspinauth(pin, clientDataHash, rp, user)
def misspinauth(pin, clientDataHash, rp, user):
    permission = 4 
    pinToken, pubkey = getPINtokenPubkey(pin,permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x02  # enumerateRPsBegin
    pinUvAuthParam = util.hmac_sha256(pinToken, bytes([subCommand]))[:16]
    apdu = getCredsMetadata_APDU_without_pinauth(subCommand)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateRPsBegin (subCommand 0x02)", checkflag=True)


def getCredsMetadata_APDU_without_pinauth(subCommand):
    cbor_map = {
        0x01: subCommand,          # subCommand
        0x03: 2                  # pinUvAuthProtocol = 2
        
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    cbor_hex = cbor_bytes.hex().upper()
    lc = len(cbor_bytes) + 1 
    util.printcolor(util.BLUE, cbor_hex)
    util.hex_string_to_cbor_diagnostic(cbor_hex)
    apdu = "80108000" + format(lc, "02X") + "0A" + cbor_hex
    return apdu