import util
import make_credential_request 
import os 
import credProtect
import getAsseration
import cbor2
import getasserationrequest
import makecredResponse
#####case 1
def maxCredBlobLength(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredBlob ****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Check that GetInfo contains maxCredBlobLength(0x0F) field, and it is at least 32.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)

##### case 2
def test_credblob_extension(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredBlob ****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Create a new discoverable credential, with "extensions" containg valid "credBlob" extension set to a random buffer, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send GetAssertion request with credBlob extension set to true, and check that result contains credBlob extension with expected bytes.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    credBlob={"credBlob": cred_blob}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credBlob)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    authdata =makecredResponse.extract_authdata_from_makecredential_response(result)
    credential_info = makecredResponse.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken, pubkey =make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credentialId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

#####case 3

def test_credblob_extension_empty_return(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredBlob ****")
    util.printcolor(util.YELLOW, """Test started: P-3
        Create a new discoverable credential and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send GetAssertion request with credBlob extension set to true, and check that result contains credBlob extension with empty BYTE STRING.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    credBlob={"credBlob": cred_blob}
    apdu=make_credential_request.createCBORmakeCred(clientDataHash, rp, user,pubkey,pinAuthToken)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    print("response",result)
    authdata=makecredResponse.extract_authdata_from_makecredential_response(result)
    print("authdata (hex):", authdata.hex())
    credential_info = makecredResponse.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credId",credentialId)
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken, pubkey =make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credentialId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)



###testing 
def test_credblob_extension1(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredBlob ****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Create a new discoverable credential, with "extensions" containg valid "credBlob" extension set to a random buffer, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send GetAssertion request with credBlob extension set to true, and check that result contains credBlob extension with expected bytes.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    cred_blob = os.urandom(32) 
    credBlob={"credBlob": cred_blob}
    apdu=credProtect.createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credBlob)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    print("response",result)
    authdata=extract_authdata_from_makecredential_response(result)
    print("authdata (hex):", authdata.hex())
    credential_info = getAsseration.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credId",credentialId)
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken, pubkey =make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credentialId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)


import cbor2

def extract_authdata_from_makecredential_response(hex_response):
    response_bytes = bytes.fromhex(hex_response)

    # Check status byte
    if response_bytes[0] != 0x00:
        raise ValueError(f"CTAP error: 0x{response_bytes[0]:02X}")

    # Decode CBOR response
    cbor_payload = response_bytes[1:]
    decoded_cbor = cbor2.loads(cbor_payload)

    print("Decoded CBOR keys:", decoded_cbor.keys())  # Should show [1, 2, 3]

    # Extract authData (it's under key 2)
    authdata = decoded_cbor.get(2)
    if not isinstance(authdata, bytes):
        raise TypeError("authData must be of type bytes")

    # print("authdata (hex):", authdata.hex())
    return authdata



    
def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]
    extensions={"credBlob": True}

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extension     =cbor2.dumps(extensions).hex().upper()        # 0x04: extensions 
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


