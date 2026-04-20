import util
import cbor2
import getAsseration
import setpin
import os
def residentKey():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.""");


def residentKeyrk():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-2: FOR AUTHENTICATORS WITHOUT A DISPLAY AND PERFORM NO VERIFICATION
        Send three valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, and if authenticator supports UV option set "uv" to false, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with no allowList presented, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 3.
        Send authenticatorGetNextAssertion(0x08), until numberOfCredentials is 1, retrieve responses and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for each of the requests. Check that response.user ONLY contains id field and nothing else!""");
   
def numberOfRpId(cryptohash, rp):
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    
    # 5-element map
    dataCBOR = "A2"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    
    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    

def checkingUVOption(curpin,user,display,rp):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-3: FOR AUTHENTICATORS WITHOUT A DISPLAY AND USE EITHER UV OR CLIENTPIN
        If UV option is supported, configure UV, else set new pin, and run registrations with pin.
        Send two valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, and if authenticator supports UV option set "uv" to true, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with no allowList presented, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 2.
        Send authenticatorGetNextAssertion(0x08), until numberOfCredentials is 1, retrieve responses and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for each of the requests. Check that response.user contains all of the registered userInfo""");
    util.APDUhex("80100000010400","GetInfo")
    setpin.clientPinSet(curpin)
    uvNotSupported(curpin,user,display,rp)


def uvNotSupported(curpin,user,display,rp):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    hashchallenge = os.urandom(32)

    pinToken, pubkey =getAsseration.getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, hashchallenge)
    util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = getAsseration.createCBORmakeCred(hashchallenge, rp, user, pubkey, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
   

def AuthenticateUser(pin, rp):
    cryptohash = util.sha256(os.urandom(32) )
    result =  optionUpSet(pin, cryptohash, rp)
    util.APDUhex("80100000010800","GetNexAsseration") 

def optionUpSet(curpin, clientDataHash, rp):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.ResetCardPower()
    util.ConnectJavaCard()

    pinToken, pubkey = getAsseration.getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeOptionU(clientDataHash, rp, pinAuthToken)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result

def createCBORmakeOptionU(cryptohash, rp, pinAuthToken):
    

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

    # 5-element map
    dataCBOR = "A4"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    util.printcolor(util.BLUE, dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


def authenticatorDisplay():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****  Resident Key****")
    util.printcolor(util.YELLOW,"""Test started: P-4: FOR AUTHENTICATORS WITH DISPLAY
        Send three valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Send three CTAP2 authenticatorGetAssertion(0x02) messages, with no allowList presented, asking using in a random order to select credentials, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 1.""");
