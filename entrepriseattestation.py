import cbor2
import binascii
import util
import credentialManagement
import authenticatorConfig
import make_credential_request
from textwrap import wrap


def enableEP(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    permission = 0x20  # authenticator config
    pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    subCommand = 0x01
    apdu=authenticatorConfig.enableEnterpriseAttestation(pinToken,subCommand)
    response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) :  enableEnterpriseAttestation(0x01)", checkflag=True)
    epenable(pin)
    util.APDUhex("80100000010400", "Get Info")

##### case:1

def  epenable(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: P-1
        Create a new credential with extensions containing minPinLenth set to True, and check that authenticator succeeds
        Check that MakeCredential response extensions contain minPinLength extension.
        If authenticator supports GetInfo minPINLength, check that minPinLength extension result equal to GetInfo.minPINLength.""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    make_credential_request.getPINtokenPubkey(pin);

##### case:2  

def authenticatorMakeCredential(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: P-2: FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that:
        1) Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        2) Attestation.fmt is "packed"
        3) Attestation.attStmt.x5c batch certificate list is exactly 1 certificate long
        4) Attestation.attStmt.x5c fist certificate matches the required for test EPBatchCertificate
        b) Attestation.epAtt is a boolean and is set to true.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    attestationdata=format(0x01, '02X')
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken,attestationdata);
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


##### case :3
def authenticatorMakeCredentials(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: P-3: FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x02, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    attestationdata=format(0x01, '02X')
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken, attestationdata);
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

##### case :4

def consumerProfile(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-1:FOR CONSUMER PROFILE
        If vendor did NOT selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by checking that GetInfo.options.ep options IS undefined!.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    make_credential_request.getPINtokenPubkey(pin);
##### case :5
def notEnterPrise(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-2:FOR CONSUMER PROFILE
        If vendor did NOT selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x01, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_PARAMETER(0x02) error code.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    make_credential_request.getPINtokenPubkey(pin);

##### case :6
def notSupportconsumer(pin):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-3:FOR CONSUMER PROFILE
        If vendor did NOT selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to 0x02, wait for the response, and check that Authenticator returns CTAP1_ERR_INVALID_PARAMETER(0x02) error code.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    make_credential_request.getPINtokenPubkey(pin);

##### case :7
def randomAttestionData(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-4: FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to RANDOM TYPE, wait for the response, and check that Authenticator returns an error.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    # taking random attestion 
    attestationdata = 'abcd'
    print(f"Before cbor_attestation, attestationdata: {attestationdata}")
    cbor_attestion     = cbor2.dumps(attestationdata).hex().upper()
    print(f"cbor_attestation: {cbor_attestion}")
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken,cbor_attestion);
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

##### case :8

def attestionvalueisNotMatch(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-5:FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the test RPID "enterprisetest.certinfra.fidoalliance.org", and enterpriseAttestation set to a number that is NOT 0x01 and NOT 0x02, wait for the response, and check that Authenticator returns CTAP2_ERR_INVALID_OPTION(0x2C) error code.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    attestationdata=format(0x08, '02X') #except 0x01 and 0x02
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken,attestationdata);
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



def wrongrpId(pin,clientDataHash,rp,user):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "**** Enterprise Attestation ****")
    util.printcolor(util.YELLOW, """Test started: F-6:FOR ENTERPRISE PROFILE
        If vendor selected Security Enterprise Profile: Check that authenticator supports Enterprise Attestation by sending a valid CTAP2 authenticatorMakeCredential(0x01) message with, RPID set to the WRONG RPID, and enterpriseAttestation set 0x01,  wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and make sure that normal, NON-Enterprise attestation is returned.""")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "Get Info")
    pinToken, pubkey=make_credential_request.getPINtokenPubkey(pin);
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")
    attestationdata=format(0x01, '02X') 
    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pubkey, pinAuthToken,attestationdata);
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







def createCBORmakeCred(clientDataHash, rp, user, credParam, pinAuthToken,attestationdata):

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
    
    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "02"               # pin protocol V2 assumed
    dataCBOR = dataCBOR + "0A"+ attestationdata   #enterpriseAttestation

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
   