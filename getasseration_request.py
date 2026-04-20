import util
import os
import binascii
import cbor2

def authenticatorGetAssertion(pin, rp,credentialId):
    hashchallenge = os.urandom(32);


    util.printcolor(util.YELLOW,"**** GetAssertion Request****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    result = GetAssertion(pin, hashchallenge, rp, credentialId)

    # Show the RP ID (domain) as part of the result
    return {
        "id": rp,              # This shows "localhost" or whatever the RP is
        "response": result     # The raw response from makeCred
    }

def GetAssertion(curpin, clientDataHash, rp,credentialId):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    getAsserationAPDU = createCBORmakeCred(clientDataHash, rp, pubkey, pinAuthToken,credentialId);
    last_response = None
    last_status = None
    for apdu in getAsserationAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
   

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

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createCBORmakeCred(cryptohash, rp, credParam, pinAuthToken,credentialId):
    PublicKeyCredentialRpEntity = {
        "id": rp
    }
    credId = [
        {  "id" :credentialId,"type" : "public-key"
        } 
    ]

    rphash = util.sha256(rp.encode()).hex()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()
    cbor_credId        = cbor2.dumps(credId).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ cbor_rp
    dataCBOR = dataCBOR + "02"+ cbor_hash
    dataCBOR = dataCBOR + "03"+ cbor_credId  
    dataCBOR = dataCBOR + "06"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "07"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 02 command for CBOR data passed

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "02" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes) 
