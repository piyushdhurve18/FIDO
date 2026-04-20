import clientprotocol1
import clientprotocol2
####################
#   [Status]
#      Works
#
#   [Author]
#     REDPATH
#
#   [Use]
#      python3 register.py
#          or 
#      python3 register.py --curl on
#
#   [Intent]
#    The intent of this code is to show all the APDUs needed to register a User at the Fido Server.
#    There are no convoluted class overloads and python source data class initializations. Basically
#    the confusing mess from Fido Alliance for test samples is gone. Yes thats right the pain is just gone.
#
#     Look at __main__ to start
#
#     1 Goto to the Fido Server to register a user and get the challenge
#     2 Sign the challenge and build a register complete package
#     3 Send this make Credential to the Fido Server to register
#
#
#   [Results]
#     Result is a CBOR output that looks like his
#     def  makeCred(pin, hashchallenge, rp, username):
#
#     {
#         1: "packed",
#         2: h'49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763
#              45000000013f59672f20aa4afeb6f47e5e916b6d980040ba6d46c7fe3577db43
#              30bab597aa0127f80c48d701b1d025cd6b252bd73095a0d61ae00db2f53d962b
#              97a913a69ed61b42e29d98b7012b52a3d07e3a47f8e0daa50102032620012158
#              20be2b5c5ab02d0c4db7680df9dbb5d12ae738bc855c8904754d281510e4812c
#              cd2258200bbeeb14c9e99f28814ae09171b9456f1867b6937e7fb927ad16c7ac
#              206e784b',
#         3: {
#             "alg": -7,
#             "sig": h'304402202b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb4902200368aba8437e9b1bf347bf0b62db65a11b1a1d1bb9cb2a1710e3014c6d6f1f67',
#             "x5c": [
#                 h'308202763082021da0030201020202101a300a06082a8648ce3d040302308199
#                   310b30090603550406130255533113301106035504080c0a4e6577204a657273
#                   65793111300f06035504070c08536f6d6572736574311a3018060355040a0c11
#                   436f6d706f5365637572652c20496e632e31223020060355040b0c1941757468
#                   656e74696361746f72204174746573746174696f6e3122302006035504030c19
#                   436f6d706f536563757265204649444f3220526f6f742043413020170d323230
#                   3930393036353132355a180f32303532303930313036353132355a30818e310b
#                   30090603550406130255533113301106035504080c0a4e6577204a6572736579
#                   3111300f06035504070c08536f6d6572736574311a3018060355040a0c11436f
#                   6d706f5365637572652c20496e632e31223020060355040b0c1941757468656e
#                   74696361746f72204174746573746174696f6e3117301506035504030c0e4172
#                   63756c7573204649444f20323059301306072a8648ce3d020106082a8648ce3d
#                   03010703420004306380daba7b87d2e4f2ba51aa3436f8ef6494d9c4c967a44b
#                   7c96e0c4aa6181e1b670f8a7bfe87b7bd97ad0ebafd9e362cecf666d60c90593
#                   d8d9d95310561ba35c305a30090603551d1304023000300b0603551d0f040403
#                   0205e0301d0603551d0e04160414c70368b89f5ec242a1e10824f83e865e36da
#                   42e23021060b2b0601040182e51c010104041204109d3df6ba282f11eda26102
#                   42ac120002300a06082a8648ce3d040302034700304402205460e9fe0017d252
#                   13c62845abd1ab80ae5159234ccb8c04d486b8538445b5ab0220567e359ca16d
#                   4cc2fbd5f4b30ddfdbc9af5b9eabbd2a76b9f4add3842a21401a',
#             ],
#         },
#     }
#   [Install]
#
#     pip3 install smartcard
#     pip3 install cbor2
#     pip3 install python-secrets
#     pip3 install cryptography
#######################
import requests, util, secrets, cbor2,struct
import binascii, os, json, base64
import getasserationrequest
from textwrap import wrap

FIDOconveyance     = "none" ; 
FIDOattachment     = "cross-platform"; 
FIDOverification   = "preferred";
RP_domain          = "localhost"
beginfidoserverURL = "http://localhost:5001/fidoapi/register/begin"
completefidoserverURL = "http://localhost:5001/fidoapi/register/complete"



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
#      {
#          1: h'b7e7534254948a9a9827e5cac4821d4caa116365acca283f0ca32cb7ff889e04',
#          2: {"id": "localhost", "name": "localhost"},
#          3: {
#              "id": h'707974686f6e40617263756c75732e636f',
#              "name": "python@arculus.co",
#              "displayName": "python@arculus.co",
#          },
#          4: [
#              {
#                  1: 2,
#                  3: -25_0,
#                  -1: 1,
#                  -2: h'498d083268167f377ac237e9ff638cedd320eb019540194f40aa5303395547db',
#                  -3: h'7c7b391ba2a1481d5b5ab22a2984a744c0e9632dc2b44fe2f5d03df5b4137ca2',
#              },
#          ],
#          8: h'bc78fe13c21914a75cf408425dde5427',
#          9: 2,
#      }
#  !!! This uses PROTOCOL V2 
#################################
def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
        "id": rp,  # id: unique identifier
         "name": rp  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
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




#############
#  [Info]
#    params:
#            curpin:  pin as string
#    clientDataHash: Is this the challenge hashed?
#                rp: This is the relying party (domain) as a string
#              user: The user to be at that RP
#  result: 009000 success
################################






def makeCred(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result

def makeCredProtocol1(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = clientprotocol1.getPINtokenPubkey1_2_2(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    # pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken)
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result

################
#  JavaCard note uses
#      ES256 (ECDSA with SHA-256)
#################################
def RegisterUser(pin, username, display, rp):
   # util.printcolor(util.YELLOW,"****Attempt to Register with Fido Server****")
   #  data= {
   #         "displayName"     : "Python",
   #        "username"        :  username,
   #        "userVerification": FIDOverification,
   #        "attestation"     : FIDOconveyance,
   #        "attachment"      : "all",
   #        "algorithms"      : ["es256"],
   #        "discoverable_credential":"preferred"}

        # session = requests.Session()
    # response = session.post(beginfidoserverURL, json=data, headers={"Content-Type": "application/json; charset=utf-8"})
    # if response.status_code != 200:
   #    util.printcolor(util.RED,f"***Fido Server connect Begin Register failed {response.status_code} ****")
   #    os._exit(0)
    # jsondata      = response.json()
    # challenge     = jsondata["challenge"]
    # decoded       = base64.urlsafe_b64decode(challenge + "==")
    # hashchallenge = util.sha256(decoded);
    hashchallenge = os.urandom(32);


    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    #print(f"Challenge: {challenge}")
    #print(json.dumps(jsondata, indent=4))

    #util.printcolor(util.YELLOW,"****Use Java Card to make Credential****")
    result = makeCred(pin, hashchallenge, rp, username)
    util.printcolor(util.YELLOW,"****The Credential is below****")

    util.hex_string_to_cbor_diagnostic( result[2:] )
    attestation_object = binascii.unhexlify(result[2:])
    attestation_data   = cbor2.loads(attestation_object)

    util.printcolor(util.YELLOW,"****Fido Server Register the Credential NOW!! ****")
    clientDataJSON = {     "type":  "webauthn.create",
                      "challenge":  "KnJpY2hhcmRyZWRwYXRoKg",
                         "origin":  "https://"+rp}

    clientDataStr = json.dumps(clientDataJSON)    
    clientDataJSONbase64 = base64.urlsafe_b64encode(clientDataStr.encode()).rstrip(b'=').decode('utf-8')

    cborAuthData= {
             "fmt": "none",
         "attStmt": {},
        "authData": attestation_data[2]
        }
    hexAuth                     = cbor2.dumps(cborAuthData).hex().upper()
    b                           =  bytes.fromhex(hexAuth)
    attestationObjectCBORBase64 = base64.urlsafe_b64encode(b).decode('utf-8')    

    id =  username
    idbase64 = base64.urlsafe_b64encode(id.encode()).decode('utf-8')

    complete ={           "type": "public-key",
                            "id": idbase64,
                         "rawId": idbase64,
       "authenticatorAttachment": "cross-platform",
                      "response": {
                                   "clientDataJSON": clientDataJSONbase64,
                                   "attestationObject": attestationObjectCBORBase64,
                                   "transports": [
                                                  "nfc",
                                                  "usb"
                                                 ]
                                  },
       "clientExtensionResults": {}
       }
    cbor_encoded_hex = cbor2.dumps(complete).hex()
    return cbor_encoded_hex


  #  response = session.post(completefidoserverURL, json=complete, headers={"Content-Type": "application/json; charset=utf-8"})
   # if response.status_code != 200:
   #     util.printcolor(util.RED,f"****Complete Register failed {response.status_code} ****")
   #     util.printcolor(util.RED,f"****Response {response.json()} ****")
   #     os._exit(0)
    #util.printcolor(util.ORANGEBLACK,"***********************Success Registered at Fido Server ")
    #os._exit(1)



    ##Call the register complete to the Fido Server last where is the signature from the Challenge by the Java Card?

####failed case 1

def clientDataHash(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-1
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "clientDataHash" is missing, wait for the response, and check that Authenticator returns an error.""")
    util.printcolor(util.YELLOW,"")
    result = missing_clinetdatahash(pin, hashchallenge, rp, username)
    


def missing_clinetdatahash(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = makeCredWithouclientDataHash(rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def makeCredWithouclientDataHash(rp, user, credParam, pinAuthToken):

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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    option  = {"rk": True}

    #cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A6"
   # dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

   # util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand


####failed case 2

def clientDataHashNotArray(pin, username, display, rp):
    hashchallenge = 12345678  # Intentionally NOT a byte array (invalid CBOR type for testing)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, """Test started: F-2
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "clientDataHash" is NOT of type BYTE ARRAY, wait for the response, and check that Authenticator returns an error.""")
    result = invalid_clientDataHash_type(pin, hashchallenge, rp, username)

def invalid_clientDataHash_type(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f" Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)

    # Convert clientDataHash to bytes for HMAC ONLY
    if isinstance(clientDataHash, str):
        clientDataHash_bytes = clientDataHash.encode('utf-8')
    elif isinstance(clientDataHash, int):
        clientDataHash_bytes = clientDataHash.to_bytes((clientDataHash.bit_length() + 7) // 8 or 1, 'big')
    elif isinstance(clientDataHash, bytes):
        clientDataHash_bytes = clientDataHash
    else:
        raise ValueError("Unsupported clientDataHash type for HMAC")

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash_bytes)
    util.printcolor(util.CYAN, f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = clientDataHashNotByte(clientDataHash, rp, user, pubkey, pinAuthToken)
    result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    print(f"Received Data: {result}")
    return result

def clientDataHashNotByte(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id": user.encode(),
        "name": user,
        "displayName": user,
    }

    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name": rp,
    }

    pubKeyCredParams = [
        {"alg": -7, "type": "public-key"},
        {"alg": -257, "type": "public-key"},
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()  # Intentionally bad type
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol = 2

    length = (len(dataCBOR) >> 1) + 1  # account for 0x01 CBOR command byte

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" + format(length, '02X') + "01" + dataCBOR
    return APDUcommand

#failed case 3

def rpIsMissing(pin, username, display):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-3
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp" is missing, wait for the response, and check that Authenticator returns an error.""")
    result = missingRP(pin, hashchallenge, username)


def missingRP(curpin, clientDataHash, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")   
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = rpDataMissing(clientDataHash, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def  rpDataMissing(clientDataHash, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    option  = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ cbor_hash
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

#failed case 4
def rpNotmap(pin, username, display):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-4
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp" is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""")
    result = rpNotMap(pin, hashchallenge, username)

def rpNotMap(curpin, clientDataHash,user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")  
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = rpIsNotMap(clientDataHash, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def rpIsNotMap(clientDataHash, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
    
      #"rp" is NOT of type MAP  
    PublicKeyCredentialRpEntity = []
    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
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

#failed case 5
def userDataMissing(pin,display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-5
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "user" is missing, wait for the response, and check that Authenticator returns an error.""")
    result = missingUser(pin, hashchallenge, rp)

def missingUser(curpin, clientDataHash, rp):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = userMissing(clientDataHash, rp, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def userMissing(clientDataHash, rp,credParam, pinAuthToken):
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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    option  = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand


###### failed case 6
def userDataNotMap(pin,display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-6
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "user" is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""")
    result = userNotMap(pin, hashchallenge, rp)


def userNotMap(curpin, clientDataHash, rp):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = userNotTypeOfMap(clientDataHash, rp, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def userNotTypeOfMap(clientDataHash, rp, credParam, pinAuthToken):

    # Invalid user field — should be a MAP, we give a string
    PublicKeyCredentialUserEntity = 1763
        
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
        {
            "alg": -257,  # RS256
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


###### failed case 7
def pubKeyCredParamsDataMissing(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-7
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" is missing, wait for the response, and check that Authenticator returns an error.""")
    pubKeyCredParamsMissing(pin, hashchallenge, rp, username)

def pubKeyCredParamsMissing(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = pubKeyCredParamsIsMissing1(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    print("Data received:", result, hex(status))
    return result


def pubKeyCredParamsIsMissing1(clientDataHash, rp, user, credParam, pinAuthToken):

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


    option  = {"rk": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()
    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand

#failed case 8
def pubKeyCredParamsDataNotArray(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-8
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" is NOT of type ARRAY, wait for the response, and check that Authenticator returns an error.""")
    result = pubKeyCredParamsNotArray(pin, hashchallenge, rp, username)


def pubKeyCredParamsNotArray(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = pubKeyCredParamsNotTypeOfArray(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def pubKeyCredParamsNotTypeOfArray(clientDataHash, rp, user, credParam, pinAuthToken):

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
#pubKeyCredParamsNotArray
    pubKeyCredParams  = "yuH_McGo2zVYVwPARKBr"
    
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


##### failed case 9
def excludeListDataNotSequence(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-9
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that is NOT of type SEQUENCE, wait for the response, and check that Authenticator returns an error.""")
    result = excludeListNotSequence(pin, hashchallenge, rp, username)


def excludeListNotSequence(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = excludeListNotTypeSequence(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def excludeListNotTypeSequence(clientDataHash, rp, user, credParam, pinAuthToken):

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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    # Intentionally invalid excludeList (not a sequence)
    excludeListData = 11553

    # Correct CBOR encoding
    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    excludeList = cbor2.dumps(excludeListData).hex().upper() 

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05" + excludeList  # intentionally NOT a sequence
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # PIN protocol

    length = (len(dataCBOR) >> 1) + 1

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" + format(length, '02X') + "01" + dataCBOR
    return APDUcommand



#failed case 10
def extensionsDataNotMap(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-10
    Send CTAP2 authenticatorMakeCredential(0x01) message, with "extensions" that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""")
    result = excludeListNotSequence(pin, hashchallenge, rp, username)


def excludeListNotSequence(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = excludeListNotTypeSequence(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def excludeListNotTypeSequence(clientDataHash, rp, user, credParam, pinAuthToken):

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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    # Intentionally invalid extensions (0x06)(not a sequence)
    extensionsData = []

    # Correct CBOR encoding
    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    extensions = cbor2.dumps(extensionsData).hex().upper() 

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "06" +  extensions 
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # PIN protocol

    length = (len(dataCBOR) >> 1) + 1

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" + format(length, '02X') + "01" + dataCBOR
    return APDUcommand


##### failed case 11
def optionsDataNotMap(pin, username, display, rp):
    hashchallenge = os.urandom(32);
    util.printcolor(util.YELLOW,"****MakeCredential Request****")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"""Test started: F-11
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "options" that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""")
    result = optionsNotMap(pin, hashchallenge, rp, username)


def optionsNotMap(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = optionsIsNotMap(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result

def optionsIsNotMap(clientDataHash, rp, user, credParam, pinAuthToken):

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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]

    option  =True

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


    


#failed case 19
def pubKeyCredParamsDataNotMap(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-1
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains an item of type NOT a MAP, wait for the response, and check that Authenticator returns an error.""")
    result = pubKeyCredParamsNotMap(pin, hashchallenge, rp, username)


def pubKeyCredParamsNotMap(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = pubKeyCredParamNotMap(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def pubKeyCredParamNotMap(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
        {"type": "public-key", "alg": -7},
        []
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)
    



#failed case 20
def pubKeyCredParamsDataIsMissing(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """TTest started: F-2
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" field that is missing, wait for the response, and check that Authenticator returns an error.""")
    result = pubKeyCredParamsIsMissing(pin, hashchallenge, rp, username)


def pubKeyCredParamsIsMissing(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = pubKeyCredParamsMissing1(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def pubKeyCredParamsMissing1(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
        { "alg": -7}
        
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)



#failed case 21
def PublicKeyCredentialParametersDataNotText(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-3
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" field that is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""")
    result = PublicKeyCredentialParametersNotText(pin, hashchallenge, rp, username)


def PublicKeyCredentialParametersNotText(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublicKeyCredentialParametersNotTypeText(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublicKeyCredentialParametersNotTypeText(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"type": "public-key", "alg": -7},
       {"type":[], "alg": -7},    
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)
    


#failed case 22
def PublicKeyCredentialParametersALGmissing(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-4
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "alg" field is missing, wait for the response, and check that Authenticator returns an error.""")
    result = PublicKeyCredentialParametersALGMissing(pin, hashchallenge, rp, username)


def  PublicKeyCredentialParametersALGMissing(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublicKeyCredentialParametersALG_Missing(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublicKeyCredentialParametersALG_Missing(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"type": "public-key", "alg": -7},
       {"type":"public-key"},    
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)
    

#failed case 23
def PublicKeyCredentialParametersALGInteger(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-5
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "alg" is NOT of type INTEGER, wait for the response, and check that Authenticator returns an error.""")
    result = algNotInteger(pin, hashchallenge, rp, username)


def  algNotInteger(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = algNotTypeInteger(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def algNotTypeInteger(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"type": "public-key", "alg": -7},
       {"type":"public-key","alg":{}},    
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)



#failed case 24
def PublicKeyCredentialParametersALGNotSupported(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-6
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams", only containing a "PublicKeyCredentialParameters" with "alg" set to unsupported by the authenticator algorithm, wait for the response, and check that Authenticator returns error CTAP2_ERR_UNSUPPORTED_ALGORITHM(0x26).""")
    result = algSetunsupported(pin, hashchallenge, rp, username)


def  algSetunsupported(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = algSetTounsupported(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def algSetTounsupported(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg": 69,"type": "public-key"},  
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)
    

    
#failed case 25
def PublicKeyCredentialParametersPublickeyNotSupported(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 4****")
    util.printcolor(util.YELLOW, """Test started: F-7
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" is NOT set to "public-key", wait for the response, and check that Authenticator returns error CTAP2_ERR_UNSUPPORTED_ALGORITHM(0x26).""")
    result = PublicKeyNotSupported(pin, hashchallenge, rp, username)


def  PublicKeyNotSupported(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublickeyNotSupported(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublickeyNotSupported(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "avocado"},  
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)

#pass case 2
def ExckudeList(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT set to "public-key", wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    result = PublicKeyCredentialDescriptor(pin, hashchallenge, rp, username)


def PublicKeyCredentialDescriptor(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublicKeyCredentialDescriptorDescriptor(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublicKeyCredentialDescriptorDescriptor(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
        {
            "id": bytes.fromhex("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"),  # dummy credentialId
            "type": "invalid-key-type"  # <--- invalid type on purpose
        }
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)


#failed case 25
def ExckudeListNotTypeMap(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: F-1
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains an element that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.""")
    result = ExckudeListNotTypemap(pin, hashchallenge, rp, username)


def ExckudeListNotTypemap(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = ExckudeListNotTypeOfmap(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def ExckudeListNotTypeOfmap(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"alg":-7,"type": "public-key"},  
    ]
    excludeList = [
        {
            "id": bytes.fromhex("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"),  # dummy credentialId
            "type": "invalid-key-type" ,
        },
        False, # <--- invalid type on purpose
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)





#failed case 26
def ExckudeListPublicKeyCredentialDescriptor(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: Test started: F-2
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is missing, wait for the response, and check that Authenticator returns an error.""")
    result = PublicKeyCredentialDescriptorismissing(pin, hashchallenge, rp, username)


def PublicKeyCredentialDescriptorismissing(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = fieldTypeIsmissing(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def fieldTypeIsmissing(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    {
        "id": bytes.fromhex("26A682CB2CE66A980E122AD77BC065B8A045EF8752AC69AE8E89E9F4C68E526F")
        # <-- Missing "type" field
    }
    ]
    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)    


#failed case 27
def PublicKeyCredentialDescriptorNotTypeText(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: F-3
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""")
    result = PublicKeyCredentialDescriptorData(pin, hashchallenge, rp, username)


def PublicKeyCredentialDescriptorData(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublicKeyCredentialDescriptornotSet(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublicKeyCredentialDescriptornotSet(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    {
        "id": bytes.fromhex("26A682CB2CE66A980E122AD77BC065B8A045EF8752AC69AE8E89E9F4C68E526F"),
        "type": False  # <-- Intentional: invalid type (should be string)
    }
]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)    

#failed case 28
def PublicKeyCredentialDescriptorIdmissing(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: F-4
         Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" field is missing, wait for the response, and check that Authenticator returns an error.""")
    idFeildIsMissing1(pin, hashchallenge, rp, username)


def idFeildIsMissing1(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = PublicKeyCredentialDescriptorMissing(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def PublicKeyCredentialDescriptorMissing(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    {
        #id field is misssing
        "type": "public-key"
    }
]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)    



#failed case 29
def PublicKeyCredentialDescriptorIdnotArray(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: F-5
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" field is NOT of type ARRAY BUFFER, wait for the response, and check that Authenticator returns an error.""")
    result = IdnotARRAYBUFFER(pin, hashchallenge, rp, username)


def IdnotARRAYBUFFER(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = IdnotTypeArrayBuffer(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def IdnotTypeArrayBuffer(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    {
        "id":[],
        "type": "public-key"
    }
]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]



    else:
        return util.build_chained_apdus(payload_bytes)    
    

#failed case 30
def duplicateCredentialId(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 5****")
    util.printcolor(util.YELLOW, """Test started: F-6
        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" set to the ID of the previously registered authenticator, wait for the response, and check that Authenticator returns an error CTAP2_ERR_CREDENTIAL_EXCLUDED(0x19).""")
    result = excludeListId(pin, hashchallenge, rp, username)
    return result


def excludeListId(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    
    # Step 1: Select FIDO applet
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    # Step 2: Get pinToken and pubkey
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    # Step 3: Create MakeCredential request with an excludeList
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken);
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result


def excludeListIdIsWrong(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"alg":-7,"type": "public-key"},  
    ]

    option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

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
# ==================================================================
# Parse the CBOR MakeCredential response
# ==================================================================

def parse_make_credential_response(last_response, last_status):
    if last_status == 0x9000:
        try:
            # Convert response to bytes if it's a hex string
            if isinstance(last_response, str):
                last_response = bytes.fromhex(last_response)

            first_map_index = next((i for i, b in enumerate(last_response) if 0xA1 <= b <= 0xBF), -1)
            if first_map_index == -1:
                raise ValueError("CBOR map not found in response")

            # Decode CBOR payload
            clean_response = last_response[first_map_index:]
            decoded_cbor = cbor2.loads(clean_response)
            # Extract 'authData' from key 0x02
            auth_data = decoded_cbor.get(2)
            
            if auth_data:
                util.printcolor(util.GREEN, f"authData: {auth_data.hex()}")
                credID= parse_auth_data(auth_data)
            

            else:
                util.printcolor(util.RED, "authData (key 0x02) not found in decoded CBOR.")

        except Exception as e:
            util.printcolor(util.RED, f"Error while parsing MakeCredential response: {e}")

    return credID



def parse_auth_data(auth_data_bytes):
    """
    Parses the authData field of a MakeCredential response and returns Credential ID (bytes).
    """
    offset = 0

    rp_id_hash = auth_data_bytes[offset:offset+32]
    offset += 32

    flags = auth_data_bytes[offset]
    offset += 1

    sign_count = struct.unpack(">I", auth_data_bytes[offset:offset+4])[0]
    offset += 4

    print("RP ID Hash:", rp_id_hash.hex())
    print("Flags:", hex(flags))
    print("Sign Count:", sign_count)

    credential_id = None

    if flags & 0x40:  # attestedCredentialData present
        aaguid = auth_data_bytes[offset:offset+16]
        offset += 16

        cred_id_len = struct.unpack(">H", auth_data_bytes[offset:offset+2])[0]
        offset += 2

        credential_id = auth_data_bytes[offset:offset+cred_id_len]
        offset += cred_id_len

        pubkey = cbor2.loads(auth_data_bytes[offset:])

        print("AAGUID:", aaguid.hex())
        print("Credential ID:", credential_id.hex())
        print("Public Key:", pubkey)

    return credential_id



def idFeildIsMissing(curpin, clientDataHash, rp, user,credID):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = createCBORmakeCred1(clientDataHash, rp, user, pubkey, pinAuthToken,credID);
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result


def PublicKeyCredentialDescriptorMissin(clientDataHash, rp, user, credParam, pinAuthToken,credID):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"alg":-7,"type": "public-key"},  
    ]
    excludeList = [
        {
       "id":credID,
        "type": "public-key"
     }
    ]

    #option = {"rk": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
   # rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

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
#passed case 4
def optionsDataUnknown(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 6****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an unknown option, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    result = optionSetUnknown(pin, hashchallenge, rp, username)


def optionSetUnknown(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = optionIsUnknown(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def optionIsUnknown(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       {"type": "public-key", "alg":-7},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    
]

    option = {"makeTea": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)

#passed case 5
def uvOptionSet(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 6****")
    util.printcolor(util.YELLOW, """Test started: P-2
        If authenticator supports "uv" option, send a valid CTAP2 authenticatorMakeCredential(0x01) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UV flag set.""")
    result = uvoptionSet(pin, hashchallenge, rp, username)


def uvoptionSet(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   
#passe case 4 

def optionsDataup(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 6****")
    util.printcolor(util.YELLOW, """Test started: P-3
        If authenticator supports "up" option, send a valid CTAP2 authenticatorMakeCredential(0x01) message, options.up set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UP flag set.""")
    result = upOptionSet(pin, hashchallenge, rp, username)


def upOptionSet(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = optionUpIsSet(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def optionUpIsSet(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    
]

    option = {"up": True}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)  
    



#passe case 4 

def optionsupNotSet(pin, username, display, rp):
    hashchallenge = os.urandom(32)
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****MakeCredential Request 6****")
    util.printcolor(util.YELLOW, """Test started: F-1

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, options.up set to false, wait for the response, check that Authenticator returns an error CTAP2_ERR_INVALID_OPTION(0x2C).""")
    result =upNotSet(pin, hashchallenge, rp, username)


def upNotSet(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW, f"Using PIN data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    makeCredAPDU = optionUpIsNotSet(clientDataHash, rp, user, pubkey, pinAuthToken);
    last_response = None
    last_status = None
    for apdu in makeCredAPDU:
        response, status = util.APDUhex(apdu, None, checkflag=False)
        last_response = response
        last_status = status
        print("Data Received:", response)
    return last_response, last_status

def optionUpIsNotSet(clientDataHash, rp, user, credParam, pinAuthToken):
    PublicKeyCredentialUserEntity = {
        "id":user.encode(),
        "name":user,
        "displayName": user,
        
    }

    
    PublicKeyCredentialRpEntity = {
        "id": rp,
        "name":rp
    }

    pubKeyCredParams = [
       { "alg":-7,"type": "public-key"},  
    ]
    excludeList = [
    {
        "id": bytes.fromhex("33A40793000E9E1EBE3694F6A0F898038B410A9FABD248801F3B84A556838332"),
        "type": "public-key"
    },
    
]

    option = {"up": False}

    cbor_hash = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken = cbor2.dumps(pinAuthToken).hex().upper()
    credParam = cbor2.dumps(pubKeyCredParams).hex().upper()
    exclude_list= cbor2.dumps(excludeList).hex().upper()
    rk = cbor2.dumps(option).hex().upper()

    dataCBOR = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + credParam
    dataCBOR += "05"+exclude_list
    dataCBOR += "07" + rk
    dataCBOR += "08" + cbor_pinAuthToken
    dataCBOR += "09" + "02"  # pinProtocol
    # Prepend "01" subCommand
    final_payload = "01" + dataCBOR

    util.printcolor(util.BLUE, "Client PIN command as subcmd 0x01 make Credential: " +  final_payload)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    # Add subcommand (01) before CBOR
    fullPayload = "01" + dataCBOR
    payload_bytes = bytes.fromhex(fullPayload)

    if len(payload_bytes) <= 255:
        lc = f"{len(payload_bytes):02X}"
        apdu = "80108000" + lc + fullPayload
        util.printcolor(util.BLUE, f"Data Sent: {apdu}")
        return [apdu]
    else:
        return util.build_chained_apdus(payload_bytes)  
    



def createCBORmakeCred1(clientDataHash, rp, user, credParam, pinAuthToken,credID):

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
        {
            "alg": -257,  # RS256
            "type": "public-key"
        }
    ]
    excludeList = [
        {
       "id":bytes.fromhex(credID),
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
    exclude_list       = cbor2.dumps(excludeList).hex().upper()
    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR += "05"+exclude_list
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

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
    


#withou rp
def makeCredential(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
   # util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = withoutCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken);
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, "Client PIN command as subcmd 0x01 make Credential", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                f"Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result



def withoutCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken):

    PublicKeyCredentialUserEntity = {
                "id": user.encode(), # id: byte sequence
              "name": user,  # name 
       "displayName": user,  # displayName
      #       "icon": "https://example.com/redpath.png"  # icon (optional)
      }
        
    PublicKeyCredentialRpEntity = {
         "name": rp  # name
      #  "icon": "https://example.com/company.png"  # icon (optional)
    }

    pubKeyCredParams  = [
        {
            "alg": -7,  # ES256
            "type": "public-key"
        },
        {
            "alg": -257,  # RS256
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
    






#optimize
def run_invalid_rp_test(mode, curpin, rp, user):

    util.printcolor(util.YELLOW, "")

# ---- Test Case Descriptions ----
    if mode == "rp.id":
        util.printcolor(util.YELLOW, """Test started: F-12:
    Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.id" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""")

    elif mode == "rp.name":
        util.printcolor(util.YELLOW, """Test started: F-13:
    Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.name" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""")

    elif mode == "rp.icon":
        util.printcolor(util.YELLOW, """Test started: F-14:
     Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.icon" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.""")
    else:
        raise ValueError("Invalid mode")

    # ---- Select Applet ----
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ---- Common Inputs ----
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    # ---- Build RP Entity based on the Mode ----
    if mode == "rp.id":
        rp_entity = {"id": 12345, "name": rp}           # id not text
    elif mode == "rp.name":
        rp_entity = {"id": rp, "name": 999}             # name not text
    elif mode == "rp.icon":
        rp_entity = {"id": rp, "name": rp, "icon": True} # icon not text

    # ---- Build Final APDU Payload ----
    makeCredAPDU = makeCredentials(
        clientDataHash, rp_entity, user, pubkey, pinAuthToken
    )

    # ---- Send Short APDUs 
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(
            makeCredAPDU,
            "Client PIN command as subcmd 0x01 make Credential",
            checkflag=True
        )

    else:
        # Multi-part APDU (chained)
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(
                apdu,
                "Rest of Data:",
                checkflag=(i == len(makeCredAPDU) - 1)
            )

    return result, status



def makeCredentials(clientDataHash, rp_entity, user, pubkey, pinAuthToken):

    userEntity = {
        "id": user.encode(),
        "name": user,
        "displayName": user
    }

    params = [{"type": "public-key", "alg": -7}]
    options = {"rk": True}

    # --- CBOR Encoding ---
    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(userEntity).hex().upper()
    cbor_params  = cbor2.dumps(params).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"  # pin protocol

    fullPayload = "01" + dataCBOR
    payload = bytes.fromhex(fullPayload)

    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80108000" + lc + fullPayload

    return util.build_chained_apdus(payload)





def run_make_credential_invalid(mode, curpin, rp, user):

    util.printcolor(util.YELLOW, "")

    # ------------------------------
    #   TEST DESCRIPTIONS
    # ------------------------------
    descriptions = {
        "rp.id": """Test started: F-12:
Send CTAP2 authenticatorMakeCredential(0x01) with "rp.id" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "rp.name": """Test started: F-13:
Send CTAP2 authenticatorMakeCredential(0x01) with "rp.name" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "rp.icon": """Test started: F-14:
Send CTAP2 authenticatorMakeCredential(0x01) with "rp.icon" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "user.id": """Test started: F-1:
Send MakeCredential with "user.id" NOT BYTE ARRAY.
Wait for the response, and check that Authenticator returns an error.""",

        "user.name": """Test started: F-2:
Send MakeCredential with "user.name" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "user.displayName": """Test started: F-3:
Send MakeCredential with "user.displayName" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "user.icon": """Test started: F-4:
Send MakeCredential with "user.icon" NOT TEXT.
Wait for the response, and check that Authenticator returns an error.""",

        "pubKeyCredParams.notMap": """Test started: F-1:
Send CTAP2 MakeCredential where pubKeyCredParams contains an item NOT A MAP.
Wait for the response, and check that Authenticator returns an error.""",

        "pubKeyCredParams.typeMissing": """Test started: F-2:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" 
contains a "PublicKeyCredentialParameters" item whose "type" field is MISSING.
Authenticator must return an error.""",

        "pubKeyCredParams.typeNotText" : """Test started: F-3:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" 
contains a "PublicKeyCredentialParameters" with "type" field that is NOT of type TEXT,
wait for the response, and check that Authenticator returns an error.""",

        "pubKeyCredParams.algMissing": """Test started: F-4:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" 
contains a "PublicKeyCredentialParameters" item whose "alg" field is MISSING.
Wait for the response, and check that Authenticator returns an error.""",

        "pubKeyCredParams.algNotInt": """Test started: F-5:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" 
contains a "PublicKeyCredentialParameters" whose "alg" field is NOT of type INTEGER. 
Wait for the response, and check that Authenticator returns an error.""",

        "pubKeyCredParams.algUnsupported": """Test started: F-6:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams"
containing a PublicKeyCredentialParameters whose 'alg' field is a valid INTEGER 
but NOT supported by the authenticator. 
Authenticator must return CTAP2_ERR_UNSUPPORTED_ALGORITHM (0x26).""",
        "pubKeyCredParams.typeNotPublicKey": """Test started: F-7:
Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams"
containing a PublicKeyCredentialParameters whose 'type' field is TEXT but NOT 'public-key'.
Authenticator must return CTAP2_ERR_UNSUPPORTED_ALGORITHM (0x26).""",


    }

    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    util.printcolor(util.YELLOW, descriptions[mode])

    # ------------------------------
    #   SELECT + GETINFO
    # ------------------------------
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   COMMON FIELDS
    # ------------------------------
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)

    # ------------------------------
    #   INVALID RP
    # ------------------------------
    if mode == "rp.id":
        rp_entity = {"id": 12345, "name": rp}
    elif mode == "rp.name":
        rp_entity = {"id": rp, "name": 999}
    elif mode == "rp.icon":
        rp_entity = {"id": rp, "name": rp, "icon": True}
    else:
        rp_entity = {"id": rp, "name": rp}

    # ------------------------------
    #   INVALID USER
    # ------------------------------
    user_entity = {
        "id": user.encode(),
        "name": user,
        "displayName": user
    }

    if mode == "user.id":
        user_entity["id"] = 12345       # invalid
    elif mode == "user.name":
        user_entity["name"] = 56789     # invalid
    elif mode == "user.displayName":
        user_entity["displayName"] = False
    elif mode == "user.icon":
        user_entity["icon"] = True

    
    # ----------------------------------------------------
    #       INVALID pubKeyCredParams CASES
    # ----------------------------------------------------

    if mode == "pubKeyCredParams.notMap":
        # F-1 → One item must be NOT A MAP
        pubKeyCredParams = [
            {"type": "public-key", "alg": -7},
            []        # INVALID → Not a MAP
        ]

    elif mode == "pubKeyCredParams.typeMissing":
        # F-2 → MAP but missing "type" field
        pubKeyCredParams = [
            {"alg": -7}   # INVALID → "type" missing
        ]
    elif mode == "pubKeyCredParams.typeNotText":
        # F-3 → "type" field exists but is NOT TEXT
        pubKeyCredParams = [
        {"type": 999, "alg": -7}  # INVALID → type should be string
    ]
        
    elif mode == "pubKeyCredParams.algMissing":
        pubKeyCredParams = [
        {"type": "public-key"}   # INVALID → missing "alg"
    ]
    elif mode == "pubKeyCredParams.algNotInt":
        pubKeyCredParams = [
        {"type": "public-key", "alg": "INVALID"}  # INVALID → alg must be integer
    ]
    elif mode == "pubKeyCredParams.algUnsupported":
        # F-6 → alg is integer but unsupported by authenticator
        # Example unsupported alg → -257 (RS256), or 12345
        pubKeyCredParams = [
        {"alg": 12345,"type": "public-key"}  # VALID integer but UNSUPPORTED
    ]
    elif mode == "pubKeyCredParams.typeNotPublicKey":
        # F-7: type is TEXT but NOT "public-key"
        pubKeyCredParams = [
        {"alg": -7,"type": "wrong-key-type",}  # valid type but unsupported string
    ]

    else:
        # DEFAULT (valid)
        pubKeyCredParams = [
            {"type": "public-key", "alg": -7}
        ]

    # ------------------------------
    #   BUILD APDU
    # ------------------------------
    makeCredAPDU = build_make_cred_apdu(
        clientDataHash,
        rp_entity,
        user_entity,
        pubKeyCredParams,          
        pinAuthToken
    )

    # ------------------------------
    #   SEND APDU(S)
    # ------------------------------
    if isinstance(makeCredAPDU, str):
        result, status = util.APDUhex(makeCredAPDU, f"MakeCredential test {mode}", checkflag=True)
    else:
        for i, apdu in enumerate(makeCredAPDU):
            result, status = util.APDUhex(apdu, None, checkflag=(i == len(makeCredAPDU) - 1))

    return result, status



# ======================================================================
#   FIXED BUILDER — NOW USES PROVIDED pubKeyCredParams
# ======================================================================

def build_make_cred_apdu(clientDataHash, rp_entity, user_entity, pubKeyCredParams, pinAuthToken):

    options = {"rk": True}

    # Convert values to CBOR hex strings
    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()   # <-- FIXED
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # Build CBOR map (A7 = 7 elements)
    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params       # <-- FIXED
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"              # pinProtocol = 2

    finalPayload = "01" + dataCBOR
    payload = bytes.fromhex(finalPayload)

    # Single APDU
    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80108000" + lc + finalPayload

    # Chained APDUs
    return util.build_chained_apdus(payload)






def ExcludeListAllTest(mode, curpin, rp, user):

    util.printcolor(util.YELLOW, "")

    # ------------------------------
    #   TEST DESCRIPTIONS
    # ------------------------------

    descriptions = {
        "excludeList.typeNotPublicKey": """Test started: P-1
Send a valid CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList"
that contains a PublicKeyCredentialDescriptor whose "type" field is NOT set to "public-key".
Authenticator must return CTAP1_ERR_SUCCESS (0x00).""",

        "excludeList.notMap": """Test started: F-1
Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains
an element that is NOT of type MAP, wait for the response, and check that Authenticator
returns an error.""",
#we have to test
        "excludeList.typeMissing": """Test started: F-2
Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains
a PublicKeyCredentialDescriptor whose 'type' field is MISSING. Authenticator must return an error.""",




    }

    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    util.printcolor(util.YELLOW, descriptions[mode])

    # ------------------------------
    #   SELECT + GETINFO
    # ------------------------------
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    # ------------------------------
    #   COMMON FIELDS
    # ------------------------------
    clientDataHash = os.urandom(32)
    pinToken, pubkey = getPINtokenPubkey(curpin)
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

    # ----------------------------------------------------
    #                excludeList  (P-1 Test)
    # ----------------------------------------------------
    if mode == "excludeList.typeNotPublicKey":
        # Build excludeList with WRONG type
        excludeList = [
            {   "id": os.urandom(32) ,       # random credentialId
                "type": "wrong-type"        # INVALID → must NOT be "public-key"
                     
            }
        ]
    elif mode == "excludeList.notMap":
    # Element is NOT a MAP → violates spec
        excludeList = [
        123   # <-- Not a MAP, valid F-1 test case
    ]
    elif mode == "excludeList.typeMissing":
    # Element is MAP, but "type" is missing → invalid
     excludeList = [
        {
            "id": os.urandom(32),     # Only id, missing "type"
        }
    ]

    
    else:
        excludeList = []
    # ------------------------------
    #   BUILD APDU
    # ------------------------------
    makeCredAPDU = build_make_cred_apdu(
        clientDataHash,
        rp_entity,
        user_entity,
        pubKeyCredParams,
        excludeList,
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
                         pubKeyCredParams, excludeList, pubkey, pinAuthToken):

    options = {"rk": True}

    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_exclude = cbor2.dumps(excludeList).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # CBOR MAP (A8 = 8 entries)
    dataCBOR  = "A8"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "05" + cbor_exclude      # <-- excludeList added
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








