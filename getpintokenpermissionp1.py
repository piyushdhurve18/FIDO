import util
import cbor2
import binascii
import Setpinp22
import os
import credentialManagement
import credBlob
import struct
import hashlib
#import getpintokenCTAP2_2

RP_domain          = "localhost"
user="bobsmith"
pin="123456"

def getPinUvAuthTokenP2_2(mode,pinnotset,protocolv1):
    util.printcolor(util.YELLOW, "**** pinUvAuthToken  protocol 2.2****")
    util.ResetCardPower()
    util.ConnectJavaCard()

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
         "cmPermission": """Test started: P-1 : 
Preconditions:
1.The authenticator supports Credential Management.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 2.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required parameters.
Include the Credential Management permission (0x04) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the cm permission.""",     
       
        "acfgPermission": """Test started: P-2 : 
Preconditions:
1.The authenticator supports Authenticator Configuration (authnrCfg) functionality.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 1.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Authenticator Configuration permission (0x20) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the authnrCfg permission.""",

"mcPermission": """Test started: P-3 : 
Preconditions:

1.The authenticator supports the MakeCredential capability.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:

Step 1:
Perform the setPIN operation using Protocol 1.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the MakeCredential permission (0x01) in the permissions field.

Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the mc permission.""",

        "gaPermission": """Test started: P-4 : 
Preconditions:
1.The authenticator supports the GetAssertion capability.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 1.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the GetAssertion permission (0x02) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the ga permission.""",

       "lbwpermission": """Test started: p-6 : 
Preconditions:
The authenticator supports Large Blob Write functionality.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 1.
Expected Result: The authenticator returns CTAP2_OK.

Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Large Blob Write permission (0x10) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the lbw permission.""",
        
        "bepermission": """Test started:  : F-1
Preconditions:
1.The authenticator does not support the Bio Enrollment capability.
2.No PIN is currently set on the authenticator.
3.PIN/UV Protocol 1 is being used.

Test Steps:
Step 1:
Perform the setPIN operation using Protocol 1.
Expected Result: The authenticator returns CTAP2_OK.
Step 2:
Send a getPinUvAuthTokenUsingPinWithPermissions (0x09) request using a valid pinHashEnc and all required command parameters.
Include the Bio Enrollment permission (0x08) in the permissions field.
Expected Result:
The authenticator returns CTAP2_OK and provides a valid encrypted pinUvAuthToken that includes the be permission, even though Bio Enrollment is not supported.""",
        



    }
    if mode not in descriptions:
        raise ValueError("Invalid mode!")
    util.printcolor(util.YELLOW, descriptions[mode])

    if(protocolv1 == 1):
        if str(pinnotset).lower() == "yes": 
            if mode == "cmPermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x04  # CredentialManagement permission
                getPINtokenPubkey(mode,pin,permission)
            elif mode =="acfgPermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x20  # Authenticator Configuration permission
                getPINtokenPubkey(mode,pin,permission)
            elif mode == "mcPermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x01  # MakeCredential permission
                getPINtokenPubkey(mode,pin,permission)
            elif mode == "gaPermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x02  # GetAssertion permission
                getPINtokenPubkey(mode,pin,permission)
            elif mode == "lbwpermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x10  # Large Blob Write permission
                getPINtokenPubkey(mode,pin,permission)
            elif mode == "bepermission":
                newpinset(pin)
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x08  # Bio Enrollment permission
                getPINtokenPubkey(mode,pin,permission)
    else:
        #prtocol 2
        print("protocol 2")
        if str(pinnotset).lower() == "yes": 
            if mode == "cmPermission":
                util.printcolor(util.YELLOW,f"  PIN IS: {pin}")
                permission = 0x04  # CredentialManagement permission
                getPINtokenwithPermission(mode,pin,permission)




def getPINtokenwithPermission(mode,curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801080000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])
    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)
    pinSetAPDU =createGetPINtoken(pinHashEnc,key_agreement,permission)
    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x09 getPINtoken", checkflag=True);

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

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

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def getPINtokenPubkey(mode,pin,permission):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:")
    response, status = util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True) 
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = util.encapsulate_protocolP1(peer_key)
    util.printcolor(util.YELLOW,f"Providing Protocol2 sharesecret:{shared_secret.hex()}")
    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = util.aes256_cbc_encryptP1(shared_secret, pin_hash)
    protocol=1
    subcommand=9
    if mode =="cmPermission":
        util.printcolor(util.YELLOW, f"User providing Credential Management Permission:{permission}")
    elif mode =="acfgPermission":
        util.printcolor(util.YELLOW, f"User providing Authenticator Config  Permission:{permission}")
    elif mode == "mcPermission":
        util.printcolor(util.YELLOW, f"User providing MakeCredential  Permission:{permission}")
    elif mode == "gaPermission":
        util.printcolor(util.YELLOW, f"User providing  GetAssertion  Permission:{permission}")
    elif mode == "lbwpermission":
        util.printcolor(util.YELLOW, f"User providing Large Blob Write  Permission:{permission}")
    elif mode == "bepermission":
        util.printcolor(util.YELLOW, f"User providing Bio Enrollment  Permission:{permission}")

    
    apdu=createGetpinToken(mode,protocol,subcommand,key_agreement,pinHashEnc,permission)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)



def createGetpinToken(mode,protocol,subcommand,key_agreement,pinHashEnc,permission):
        
        cbor_cose_key= cbor2.dumps(key_agreement).hex().upper()
        cbor_pinHashEnc = cbor2.dumps(pinHashEnc).hex().upper()
        cbor_subcommand = cbor2.dumps(subcommand).hex().upper()
        cbor_protocol   = cbor2.dumps(protocol).hex().upper()
        cbor_permission = cbor2.dumps(permission).hex().upper()
        if mode=="missing.pinUvAuthProtocol":
            util.printcolor(util.YELLOW,f"  Missing pinUvAuthProtocol: ")
            data_cbor = "A3"
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x05 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
        elif mode=="cmPermission":
            
            data_cbor = "A5"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x09 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
            data_cbor += "09" + cbor_permission                   # cm permission

        else:
            data_cbor = "A5"
            data_cbor += "01" + cbor_protocol                     # pinProtocol = 1
            data_cbor += "02" + cbor_subcommand                   # subCommand = 0x09 (getPINToken)
            data_cbor += "03" + cbor_cose_key                     # keyAgreement
            data_cbor += "06" + cbor_pinHashEnc                   # pinHashEnc
            data_cbor += "09" + cbor_permission                   # cm permission
        length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
        apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
        return apdu

def newpinset(pin):
    
    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010700", "Reset Card PIN (optional)")
    util.APDUhex("00a4040008a0000006472f0001", "Re-select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = util.encapsulate_protocolP1(decoded[1])
    padded_pin = util.pad_pin_P1("123456", validate=False)  # skips min length check
    new_pin_enc = util.aes256_cbc_encryptP1(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = util.hmac_sha256P1(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)

    util.APDUhex("80100000010400", "GetInfo after SetPIN")


def create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement):
    cose_key = cbor2.dumps(key_agreement).hex().upper()
    cbor_newpin = cbor2.dumps(new_pin_enc).hex().upper()
    cbor_auth = cbor2.dumps(pin_auth).hex().upper()

    data_cbor = "A5"
    data_cbor += "01" + "01"            # pinProtocol = 1
    data_cbor += "02" + "03"            # subCommand = 3 (SetPIN)
    data_cbor += "03" + cose_key        # keyAgreement
    data_cbor += "04" + cbor_auth       # pinAuth
    data_cbor += "05" + cbor_newpin     # newPinEnc

    length = (len(data_cbor) // 2) + 1  # add 1 for the leading 0x06 tag
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor+"00"
    return apdu