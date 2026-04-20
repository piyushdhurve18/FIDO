import util
import setpin
import make_credential_request
import os
import credProtect
import credBlob
import getAsseration
import cbor2
#####case 1
def largeBlobKey(pin, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    setpin.clientPinSet("123456")
    util.APDUhex("80100000010400", "Get Info")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Create a new credential with extensions containing largeBlobKey set to True, and check that authenticator succeeds, and that MakeCredential response contains largeBlobKey(0x05) key set to a random 32 byte BYTE STRING.
        Send a corresponding new MakeCredential request and see that largeBlobKeys do not match!.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    extension={"largeBlobKey": True}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, extension)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    print("response:",result)
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    extension={"largeBlobKey": True}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, extension)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    authdata=credBlob.extract_authdata_from_makecredential_response(result)
    print("authdata (hex):", authdata.hex())
    credential_info = getAsseration.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid:",credentialId)
    return credentialId

    

##### case 2
def largeBlobKeyGetasseration(pin, rp, credId):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Send GetAssertion request for the previously registered credential with largeBlobKey extension set to true, and check that returned largeBlob key set to the previously recorded largeBlob key.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    extension={"largeBlobKey": True}
    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,extension)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


######case 3
def test_blobkey_invalid(pin, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: F-1
        Send MakeCredential request with largeBlobKey extension set to FALSE, and check that authenticator returns CTAP2_ERR_INVALID_OPTION(0x2C).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    extension={"largeBlobKey": False}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, extension)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);

#####case 4

def test_blobkey_notset(pin, rp, user):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: F-2
        Send MakeCredential request with largeBlobKey extension set to not BOOLEAN, and check that authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE(0x2C).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    extension={"largeBlobKey":{}}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, extension)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);


####case 5
def get_assertion_invalid_largeblobkey(pin, rp, credId):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: F-3    
        Send GetAssertion request for the previously registered credential with largeBlobKey extension set to FALSE, and check that authenticator returns CTAP2_ERR_INVALID_OPTION(0x2C).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    extension={"largeBlobKey": False}
    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,extension)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

####case 6

def get_assertion_random(pin, rp, credId):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Large Blob Key ****")
    util.printcolor(util.YELLOW, """Test started: F-4
        Send GetAssertion request for the previously registered credential with largeBlobKey extension set to random type, and check that authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE(0x2C).""");    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    clientDataHash=os.urandom(32)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    extension={"largeBlobKey": []}
    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId,extension)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId,extension):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]
   

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extension     = cbor2.dumps(extension).hex().upper()        # 0x04: extension
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A6"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "04" + cbor_extension
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu





    
    
