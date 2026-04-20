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
import requests, util, secrets, cbor2
import binascii, os, json, base64

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

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

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

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand




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
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
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


    util.printcolor(util.YELLOW,"****Fido Server supports****")
    #print(f"Challenge: {challenge}")
    #print(json.dumps(jsondata, indent=4))

    util.printcolor(util.YELLOW,"****Use Java Card to make Credential****")
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


  #  response = session.post(completefidoserverURL, json=complete, headers={"Content-Type": "application/json; charset=utf-8"})
   # if response.status_code != 200:
   #     util.printcolor(util.RED,f"****Complete Register failed {response.status_code} ****")
   #     util.printcolor(util.RED,f"****Response {response.json()} ****")
   #     os._exit(0)
    #util.printcolor(util.ORANGEBLACK,"***********************Success Registered at Fido Server ")
    #os._exit(1)



    ##Call the register complete to the Fido Server last where is the signature from the Challenge by the Java Card?
    

if __name__ == "__main__":
    util.ConnectJavaCard()
    RegisterUser("123456","python@arculus.co", "Platform Desktop", RP_domain)





