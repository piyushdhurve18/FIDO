import util
import hmacSecret
import os
import binascii
import cbor2
import getasserationrequest




def authenticatorClientPin():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2 ****")
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
    util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

def makecredential(clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****HMAC Secret - Strict PUAT2****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg a valid "hmac-secret" set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, with extensions payload containing 'hmac-secret' field set to true.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    extensions={"credProtect": 1,"hmac-secret":True}
    apdu=createCBORmakeCred(clientDataHash, rp, user, extensions)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result


def getAsseration(pin,rp, response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2****")
    util.printcolor(util.YELLOW, """Test started: P-3
        Send a valid CTAP2 getAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with one salt, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) Check that response contains extensions encrypted "hmac-secret" extension response. Decrypt it and save it as salt1
            (b) Send another GetAssertion with salt1 and salt2, and check that response still equal to result, and nonUvSalt2Hmac does not equal nonUvSalt1Hmac.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    key_agreement, shareSecretKey  =  getPINtokenPubkeywithkeyagremant(pin)
    print("key_agreement",key_agreement)
    # Prepare extension hmac-secret with 1 salt for protocol 2
    salt1 = os.urandom(32)
    saltEnc = aes256_cbc_encrypt(shareSecretKey , salt1)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    apdu = createCBORmakeAssertion(clientDataHash, rp,  credId,key_agreement,saltEnc,saltAuth)
   
    print("succes")
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )     
    #here add the two salt 
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    key_agreement, shareSecretKey  =  getPINtokenPubkeywithkeyagremant(pin)
    satl1=os.urandom(32)
    salt2=os.urandom(32)
    combinedata=satl1+salt2
    saltEnc = aes256_cbc_encrypt1(shareSecretKey ,  combinedata)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    apdu = createCBORmakeAssertion(clientDataHash, rp,  credId,key_agreement,saltEnc,saltAuth)
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result



def hmacsalt1andsal2(pin,rp,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2****")
    util.printcolor(util.YELLOW, """Test started: P-4
        Send a valid CTAP2 GetAssertion(0x02) message, "extensions" containing a valid "hmac-secret" extension request, with salt1 and salt2, wait for the response, and:
            (a) Check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code
            (b) Check that response extensions contain "hmac-secret" extension. Decrypt extensions
            (c) Check that decrypted hmacs contain uvSalt1Hmac, and uvSalt2Hmac
            (d) Check that uvSalt1Hmac does not equal to nonUvSalt1Hmac, an uvSalt2Hmac does not equal to nonUvSalt2Hmac.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    util.APDUhex("80100000010400", "Get Info")
    setpin(pin)
    util.ResetCardPower()
    util.ConnectJavaCard()
    pinToken,key_agreement, shareSecretKey  =  getPINtokenPubkey(pin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    satl1=os.urandom(32)
    salt2=os.urandom(32)
    combinedata=satl1+salt2
    saltEnc = aes256_cbc_encrypt1(shareSecretKey ,  combinedata)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    apdu = createCBORmakeAssertion1(clientDataHash, rp,  pinAuthToken, credId,key_agreement,saltEnc,saltAuth)
    print("succes")
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result


def randomHMAC(pin,clientDataHash, rp, user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2 ****")
    util.printcolor(util.YELLOW, """TTest started: F-1
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg "hmac-secret" set to a random type, wait for the response, and check that Authenticator returns an error.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken,key_agreement, shareSecretKey = getPINtokenPubkey(pin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    extensions={"hmac-secret":[]}
    apdu=createCBORmakeCred1(clientDataHash, rp, user,extensions,pinAuthToken)
    result,status = util.APDUhex(apdu,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def salt_length_insufficient(pin,rp, response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2****")
    util.printcolor(util.YELLOW, """Test started: F-2
        Send a CTAP2 getAssertion(0x02) message, with "extensions" containing "hmac-secret" extension request with one salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    key_agreement, shareSecretKey  =  getPINtokenPubkeywithkeyagremant(pin)
    print("key_agreement",key_agreement)
    # Prepare extension hmac-secret with 1 salt for protocol 2
    salt1 = os.urandom(10)
    saltEnc = aes256_cbc_encrypt_allow_invalid(shareSecretKey , salt1)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    apdu = createCBORmakeAssertion(clientDataHash, rp,  credId,key_agreement,saltEnc,saltAuth)
    print("succes")
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )
    return result


def salt_length_insufficient1(pin,rp, response):
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW, "**** HMAC Secret - Strict PUAT2****")
    util.printcolor(util.YELLOW, """Test started: F-3
        Send a CTAP2 getAssertion(0x02) message, with "extensions" containg a "hmac-secret" extension request with two salts, with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error.""")
    clientDataHash= util.sha256(os.urandom(32) )
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")
    util.APDUhex("80100000010400", "Get Info")

    util.ResetCardPower()
    util.ConnectJavaCard()
    key_agreement, shareSecretKey  =  getPINtokenPubkeywithkeyagremant(pin)
    print("key_agreement",key_agreement)
    # Prepare extension hmac-secret with 1 salt for protocol 2
    salt1 = os.urandom(32)
    salt2 =os.urandom(10)
    combinsalt=salt1+salt2
    saltEnc = aes256_cbc_encrypt_allow_invalid(shareSecretKey , combinsalt)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:32]
    apdu = createCBORmakeAssertion(clientDataHash, rp,  credId,key_agreement,saltEnc,saltAuth)
    print("succes")
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )
    return result

def setpin(pin):
    cardPublickey, status= util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True);
    


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

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand
def aes256_cbc_encrypt2(shared_secret, data):
    """
    Encrypts 32 bytes of data with AES-256-CBC.
    Uses the *last* 32 bytes of shared_secret as the AES key.
    """
    assert len(data) == 32, "FIDO2 hmac-secret requires exactly 32 bytes input"
    aes_key = shared_secret[32:]  # Discard first 32 bytes
    iv = os.urandom(16)           # Random IV for each encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = cipher.update(data) + cipher.finalize()
    return iv + ct  # iv || ciphertext


def hmac_sha256(shared_secret, message):
    """
    Use the first 32 bytes of shared_secret as HMAC key.
    """
    hmac_key = shared_secret[:32]  # Only first 32 bytes
    hmac_obj = hmac.new(hmac_key, message, hashlib.sha256)
    return hmac_obj.digest()
    
def makeAssertion(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard()
    key_agreement, shareSecretKey  =  getPINtokenPubkeywithkeyagremant(curpin)
    print("key_agreement",key_agreement)
    #here we support for salt 1 and sending keyaggremnt
    # Prepare extension hmac-secret with 1 salt for protocol 2
    salt1 = os.urandom(32)
    saltEnc = aes256_cbc_encrypt(shareSecretKey , salt1)
    saltAuth = hmac_sha256(shareSecretKey, saltEnc)[:16]
    apdu = createCBORmakeAssertion(clientDataHash, rp,  credId,key_agreement,saltEnc,saltAuth)
    print("succes")
    if isinstance(apdu, str):
       result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    else:
        for i, apdu in enumerate(apdu):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(apdu) - 1)
            )

    return result



def createCBORmakeCred(clientDataHash, rp, user, extensions):

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


def createCBORmakeCred1(clientDataHash, rp, user, extensions,pinAuthToken):

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

   

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_extensions    = cbor2.dumps(extensions).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
   
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "06"+ cbor_extensions
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand






def getPINtokenPubkeywithkeyagremant(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    return  key_agreement, shareSecretKey 

def aes256_cbc_encrypt1(shared_secret, data):
    """
    AES-256-CBC encrypt 32 or 64 bytes of data.
    Uses shared_secret[32:] as the AES key.
    """
    assert len(data) in [32, 64], "FIDO2 hmac-secret requires 32 or 64 bytes input"
    aes_key = shared_secret[32:]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = cipher.update(data) + cipher.finalize()
    return iv + ct  # 16 bytes IV + ciphertext (32 or 64 bytes)

def createCBORmakeAssertion(cryptohash, rp,  credId,key_agreement,saltEnc,saltAuth):
    allow_list = [{
         "id": bytes.fromhex(credId),
        "type": "public-key"
       
    }]


    hmac_secret_ext = {
        0x01: key_agreement,
        0x02:saltEnc,
        0x03:saltAuth
        
    }
    extensions = {"hmac-secret": hmac_secret_ext}
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extensions     = cbor2.dumps(extensions).hex().upper()      # 0x04: extensions
    #cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "04" + cbor_extensions 
    dataCBOR += "07" + pin_protocol

    length = (len(dataCBOR) >> 1) +1    #have to add the 02 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

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
    

def createCBORmakeAssertion1(cryptohash, rp,  pinAuthToken, credId,key_agreement,saltEnc,saltAuth):
    allow_list = [{
        "id": bytes.fromhex(credId),
        "type": "public-key"
        
    }]


    hmac_secret_ext = {
        0x01: key_agreement,
        0x02:saltEnc,
        0x03:saltAuth
        
    }
    extensions = {"hmac-secret": hmac_secret_ext}
    option ={}
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_extensions    = cbor2.dumps(extensions).hex().upper()       # 0x04: extensions
    cbor_option        = cbor2.dumps(option).hex().upper()           # 0x05: option
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 6-element map
    dataCBOR = "A7"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "04" + cbor_extensions
    dataCBOR += "05" + cbor_option
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    length = (len(dataCBOR) >> 1) +1    #have to add the 02 command for CBOR data passed

    # Diagnostic print
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

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
    






















def getAssertionWithHMACSecret(pin, clientDataHash, rpId, credId_hex,keyAgreement,saltEnc,saltAuth ):
    # Prepare allowList
    allow_list = [{
        "id": bytes.fromhex(credId_hex),
        "type": "public-key"
    }]

    

    hmac_secret_extension = {
        0x01: keyAgreement,
        0x02: saltEnc,
        0x03: saltAuth,
        0x04:2
    }

    # Prepare GetAssertion CBOR MAP
    cbor_map = {
        1: rpId,                        # rpId
        2: clientDataHash,              # clientDataHash
        3: allow_list,                  # allowList
        4: {"hmac-secret": hmac_secret_extension},
        7: 2  
    }
    data = cbor2.dumps(cbor_map)
    payload = b"\x02" + data
    apdus = hmacSecret.build_apdu_chain(payload)

    # Send chained APDU
    for i, apdu in enumerate(apdus):
        util.APDUhex(apdu, "GetAssertion (chained)" if i < len(apdus)-1 else "GetAssertion Final", checkflag=(i == len(apdus)-1))

import os
import binascii
import cbor2
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from textwrap import wrap


def getAssertion_hmacSecret_protocol2(pin, rpId, credId_hex):
    util.printcolor(util.YELLOW, "=== CTAP2.1 GetAssertion with hmac-secret, Protocol 2, 2 Salts ===")
    util.APDUhex("00A4040008A0000006472F0001", "Select Applet")

    clientDataHash = util.sha256(os.urandom(32))

    pinToken, sharedSecret, keyAgreement = getPINtokenPubkey(pin)

    # Prepare 2 salts (32 bytes each)
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    salts_concat = salt1 + salt2  # total 64 bytes

    saltEnc = aes256_cbc_encrypt(sharedSecret, salts_concat)
    saltAuth = hmac_sha256(sharedSecret, saltEnc)[:16]

    getAssertionWithHMACSecret(clientDataHash, rpId, credId_hex, keyAgreement, saltEnc, saltAuth)


def getAssertionWithHMACSecret(clientDataHash, rpId, credId_hex, keyAgreement, saltEnc, saltAuth):
    allow_list = [{
        "id": bytes.fromhex(credId_hex),
        "type": "public-key"
    }]

    hmac_secret_extension = {
        0x01: keyAgreement,
        0x02: saltEnc,
        0x03: saltAuth,
        0x04: 2  # Protocol 2
    }

    cbor_map = {
        1: rpId,
        2: clientDataHash,
        3: allow_list,
        4: {"hmac-secret": hmac_secret_extension},
        7: 2  # Protocol 2
    }

    data = cbor2.dumps(cbor_map)
    payload = b"\x02" + data
    apdus = build_apdu_chain(payload)

    for i, apdu in enumerate(apdus):
        util.APDUhex(apdu, "GetAssertion (chained)" if i < len(apdus)-1 else "GetAssertion Final", checkflag=(i == len(apdus)-1))



def aes256_cbc_encrypts(shared_secret, salt):
    """
    Encrypt 32-byte salt with AES-256-CBC (no padding, IV=0).
    """
    assert len(salt) == 32
    key = shared_secret[:32]  # or last 32 depending on spec implementation
    iv = bytes(16)            # all zeros

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(salt)  # no padding → must be exactly 32 bytes
    return ciphertext


def aes256_cbc_encrypt(shared_secret, data):
    """
    Encrypts 32 bytes of data with AES-256-CBC.
    Uses the *last* 32 bytes of shared_secret as the AES key.
    """
    assert len(data) == 32, "FIDO2 hmac-secret requires exactly 32 bytes input"
    aes_key = shared_secret[32:]  # Discard first 32 bytes
    iv = os.urandom(16)           # Random IV for each encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = cipher.update(data) + cipher.finalize()
    return iv + ct  # iv || ciphertext



def aes256_cbc_encrypt5(shared_secret: bytes, data: bytes) -> bytes:
    """
    Encrypts 32-byte salt using AES-256-CBC with FIDO2 rules:
      - AES key = full 32-byte sharedSecret (SHA256 of ECDH secret)
      - IV = 16 zero bytes (fixed, not random)
      - Data must be exactly 32 or 64 bytes
    Returns: ciphertext only
    """
    assert len(shared_secret) == 32, "shared_secret must be 32 bytes"
    assert len(data) in (32, 64), "salt must be 32 or 64 bytes"

    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()

def aes256_cbc_encrypt_allow_invalid(shared_secret, data):
    """
    Encrypts arbitrary-length data with AES-256-CBC.
    For negative test cases (e.g., non-32 or 64 byte salts).
    Uses the last 32 bytes of shared_secret as the AES key.
    Returns: IV (16 bytes) || Ciphertext
    """
    # Skip the strict assertion to allow malformed input in tests
    aes_key = shared_secret[32:]  # Use last 32 bytes
    iv = os.urandom(16)
    # Pad to block size (16 bytes)
    padded = data + b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = cipher.update(padded) + cipher.finalize()
    return iv + ct

def hmac_sha256(shared_secret, message):
    """
    Use the first 32 bytes of shared_secret as HMAC key.
    """
    hmac_key = shared_secret[:32]  # Only first 32 bytes
    hmac_obj = hmac.new(hmac_key, message, hashlib.sha256)
    return hmac_obj.digest()


def build_apdu_chain(payload_bytes):
    payload_hex = binascii.hexlify(payload_bytes).decode().upper()
    if len(payload_bytes) <= 255:
        lc = format(len(payload_bytes), '02X')
        apdu = "80108000" + lc + payload_hex
        return [apdu]
    else:
        max_chunk_size = 255 * 2
        chunks = wrap(payload_hex, max_chunk_size)
        apdus = []

        for i, chunk in enumerate(chunks):
            cla = "90" if i < len(chunks) - 1 else "80"
            ins = "10"
            p1 = "80"
            p2 = "00"
            lc = format(len(chunk) // 2, '02X')
            apdu = cla + ins + p1 + p2 + lc + chunk
            apdus.append(apdu)

        return apdus


def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtoken(pinHashEnc,key_agreement)

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

    # Decrypt the Token
    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, key_agreement, shareSecretKey


def createGetPINtoken(pinHashEnc, key_agreement):
    platformCOSKEY = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashEnc = cbor2.dumps(pinHashEnc).hex().upper()

    dataCBOR = "A4"
    dataCBOR += "01" + "02"
    dataCBOR += "02" + "05"
    dataCBOR += "03" + platformCOSKEY
    dataCBOR += "06" + cbor_pinHashEnc

    length = (len(dataCBOR) >> 1) + 1

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    return "80108000" + format(length, '02X') + "06" + dataCBOR
