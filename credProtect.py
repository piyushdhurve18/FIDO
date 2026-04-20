import util
import make_credential_request
import cbor2
import getAsseration
import os
import credentialManagement
import makecredResponse
import getasserationrequest
from textwrap import wrap
#####case 1
def makecredential(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredProtect ****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Create a new (discoverable if supported) credential, with "extensions" containing a valid "credProtect" extension set to userVerificationOptional(0x01), and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. 
        Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        If rk is supported, send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    credprotect={"credProtect": 1}
    apdu=createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credprotect)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    credId =getasserationrequest.authParasing(result)
    newClientDataHash = util.sha256(os.urandom(32))
    getassertion_apdu = createCBORmakeAssertion(newClientDataHash, rp, credId)
    result, status = util.APDUhex(getassertion_apdu, "GetAssertion 0x02", checkflag=True)
    apdu =  withoutCredId(clientDataHash, rp)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result
    

#####case 2

def testUVOptionalWithCredProtectAndAssertionFlows(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredProtect ****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Create a new (discoverable if supported) credential, with "extensions" containing valid "credProtect" extension set to userVerificationOptionalWithCredentialIDList(0x02), and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    #userVerificationOptionalWithCredentialIDList(0x02)
    credprotect={"credProtect": 2}
    apdu=createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credprotect)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    credId =getasserationrequest.authParasing(result)
    newClientDataHash = util.sha256(os.urandom(32))
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    getassertion_apdu = createCBORmakeAssertion(newClientDataHash, rp, credId)
    result, status = util.APDUhex(getassertion_apdu, "GetAssertion 0x02", checkflag=True)
    #withou cred up/uv=false
    apdu =  withoutCredId(clientDataHash, rp)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result
##### 3

def testCredProtectUVRequiredWithAssertionErrors(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredProtect ****")
    util.printcolor(util.YELLOW, """Test started: P-3
        Create a new (discoverable if supported) credential, with "extensions" containing valid "credProtect" extension set to userVerificationRequired(0x03), and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid GetAssertion(0x02) request with previously recorded credId and UV/UP set to false, and check that Authenticator returns an error
        Send a valid GetAssertion(0x02) request in RK mode(no credentialId), and UV/UP set to false, and check that Authenticator returns an error.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    #userVerificationOptionalWithCredentialIDList(0x02)
    credprotect={"credProtect": 3}
    apdu=createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credprotect)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    credId =getasserationrequest.authParasing(result)
    newClientDataHash = util.sha256(os.urandom(32))
    getassertion_apdu = createCBORmakeAssertion(newClientDataHash, rp, credId)
    result, status = util.APDUhex(getassertion_apdu, "GetAssertion 0x02", checkflag=True)
    #withou cred up/uv=false
    apdu =  withoutCredId(clientDataHash, rp)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result


####4
def  verify_cred_protect_level_with_credential_management(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** CredProtect ****")
    util.printcolor(util.YELLOW, """Test started: P-4
        If rk and CredentialManagement is supported: 
            (a) Create a new discoverable credential, with "extensions" containing  valid "credProtect" extension set to a random level. 
            (b) Call CredentialManagementAPI, find the corresponding credential, and check that credProtect level matches the set value.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    #userVerificationOptionalWithCredentialIDList(0x02)
    credprotect={"credProtect": 2}
    apdu=createCBORmakeCred(clientDataHash, rp, user,pinAuthToken, credprotect)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    permission = 4  # CredentialManagement permission
    pinToken, pubkey = credentialManagement.getPINtokenPubkey(pin,  permission)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")
    subCommand = 0x04  # enumerateCredentialsBegin
    apdu = credentialManagement.enumerateCredentials(subCommand, pinToken,rp)
    response, status = util.APDUhex(apdu, "CredentialMgmt(0A): enumerateCredentialsBegin(0x04)", checkflag=True)






def createCBORmakeCred(clientDataHash, rp, user, pinAuthToken,extension):

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
    cbor_extension   = cbor2.dumps(extension).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06"+ cbor_extension
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1  

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Final payload = 01 prefix + dataCBOR
    full_data = "01" + dataCBOR
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
    
def createCBORmakeAssertion(cryptohash, rp,  credId):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
        
    }]

    option= {"up":False}
   
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "05" + cbor_option
    dataCBOR += "07" + pin_protocol
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu
    
def withoutCredId(cryptohash, rp):
    option= {"up":False}
   
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A4"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "05" + cbor_option
    dataCBOR += "07" + pin_protocol

   
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu

