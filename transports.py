import util
import logging
import binascii
import cbor2
import os



def run_fido_applet_select():
    util.printcolor(util.YELLOW, "**** Transports ****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: P-1
    Send FIDO applet selection command and check that authenticator succeeds.
    For CTAP1(U2F) compatible authenticators, check that authenticator returns 0x5532465F5632 (U2F_V2) in response.
    For CTAP2-only authenticators, check that authenticator returns 0x4649444f5f325f30 (FIDO_2_0) in response. """)
    response = util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    def check_authenticator(response):
        response_str = response[0]
        U2F_V2 = "5532465F5632"
        FIDO_2_0 = "4649444f5f325f30"
        if response_str.upper() == U2F_V2:
            util.printcolor(util.GREEN, "Authenticator is CTAP1 (U2F) compatible (U2F_V2 detected).")
        elif response_str.upper() == FIDO_2_0:
            util.printcolor(util.GREEN, "Authenticator is CTAP2 only (FIDO_2_0 detected).")
        else:
            util.printcolor(util.RED, "Unknown authenticator type or unexpected response.")
    check_authenticator(response)

#optimize code
def run_make_credential(mode, curpin, rp, user):
    util.printcolor(util.YELLOW, "")
    # Select the test case message
    if mode == "extended":
        util.printcolor(util.YELLOW, """Test started: P-2:
    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, wrapped in Extended APDU, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    elif mode == "short":
        util.printcolor(util.YELLOW, """Test started: P-3:
    Send a valid CTAP2 authenticatorMakeCredential(0x01) message, wrapped in Short APDU, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    elif mode == "mixed":
        util.printcolor(util.YELLOW, """Test started: P-4:
     Send a valid CTAP2 authenticatorMakeCredential(0x01) message, wrapped in Short APDU with mixed sizes, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    else:
        raise ValueError("Invalid mode! Use: extended | short | mixed")
    
    # Common steps
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    # Select APDU builder
    if mode == "extended":
        makeCredAPDU, cbor = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken)
        if isinstance(makeCredAPDU, str):
            result, status = util.APDUhexExtended(
                makeCredAPDU,
                "Extended APDU MakeCredential",
                checkflag=True
            )

    elif mode in ("short", "mixed"):
        makeCredAPDU = createCBORmakeCredshort(clientDataHash, rp, user, pubkey, pinAuthToken)

        if isinstance(makeCredAPDU, str):
            result, status = util.APDUhex(
                makeCredAPDU,
                "Short APDU MakeCredential",
                checkflag=True
            )
        else:
            # Multi-part short APDU
            for i, apdu in enumerate(makeCredAPDU):
                result, status = util.APDUhex(
                    apdu,
                    "Rest of Data:",
                    checkflag=(i == len(makeCredAPDU) - 1)
                )

    return result

##### case 5
def incorrect_INS_short():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: F-1
        Send CTAP2 getInfo(0x04) with invalid INS, wrapped in Short APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80870000010400", "GetInfo")
##### case 6 
def incorrect_INS_Extended():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: F-2
        Send CTAP2 getInfo(0x04) with invalid INS, wrapped in Extended APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00).
                    """)   
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80750000000001040000", "GetInfo")
##### case 7 
def invalidLc_short():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-3
        Send CTAP2 getInfo(0x04) wrapped in Short APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000ff0400", "GetInfo")
##### case 8
def invalidLc_Extended():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-4
        Send CTAP2 getInfo(0x04) wrapped in Extended APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700).""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("801000000000ff040000", "GetInfo")







def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
   # util.printcolor(util.ORANGE,f"{pubkey}")
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

def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

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

    length = (len(dataCBOR) >> 1) +1    #have to add the 06
    cbor="01" + dataCBOR
    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "801000000000" +  format(length, '02X') + cbor
    return APDUcommand,cbor



def createCBORmakeCredshort(clientDataHash, rp, user, credParam, pinAuthToken):

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

    # Diagnostic print
    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

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
    

 
