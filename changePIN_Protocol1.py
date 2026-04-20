import util
import binascii
import cbor2
import hashlib, hmac, binascii
import cbor2
import os
import getasserationrequest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

RP_domain          = "localhost"
curpin="123456"
user="bobsmith"
new_Pin = ""
def changePin(mode, reset_required, set_pin_required):
    util.printcolor(util.YELLOW, "****CTAP 2.2****")

    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
         "minimumNewPinLength": """Test started: P-1 :
Precondition: The authenticator must be reset and have a PIN configured.
Change the existing PIN to a new valid PIN that meets the minimum allowed length, ensuring all command parameters are correct. The authenticator should respond with CTAP2_OK""",

        "maximumNewPinLength": """Test started: P-2 :
Precondition: The authenticator must be reset and have a PIN configured.
Change the existing PIN to a new valid PIN that meets the maximum allowed length, ensuring all command parameters are correct. The authenticator should respond with CTAP2_OK""",

        "validNewPinLength": """Test started: P-3 :
Precondition: The authenticator must be reset and have a PIN configured.
Change the existing PIN to a new valid PIN, ensuring all command parameters are correct. The authenticator should respond with CTAP2_OK""",

        "getPinRetries": """Test started: P-4 :
After changing a new PIN, check that the PIN retry counter is properly initialized. Use the correct getPINRetries command to retrieve the retry count. The authenticator should return the maximum allowed retries.""",

 "multipleChangePinOperation": """Test started: P-6 :
Precondition: Authenticator must be Reset and has no PIN set.
Begin by attempting the changePIN command when no PIN is set on the authenticator, ensuring all command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET. Next, set a new valid PIN with all parameters correctly specified; the authenticator should return CTAP2_OK. Then, attempt to change the PIN again with correct PIN, ensuring all parameters are correct—this time, the authenticator must return CTAP2_OK. In the same scenario, use the getPINRetries command to verify that the authenticator reports the maximum allowed PIN retry count, as expected.""",

"randomCurrentPin": """Test started: P-8 :
Precondition: The authenticator is reset and a PIN is not Set.
Attempt to change a randomly chosen valid PIN (treated as the current PIN) to a new valid PIN. Ensure all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET.""",

"newPinShorterThanMinPin": """Test started: P-9 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt Change PIN , when new PIN is shorter than minimum pin length (i.e. Current PIN is valid but new PIN is invalid), ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"newPinLongerThanMaxPin": """Test started: P-10 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt Change PIN, when new PIN is longer than maximum pin length (i.e. Current PIN is valid but new PIN is invalid), ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"curPinShorterThanMinPin": """Test started: P-11 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform change PIN with invalid current PIN which is shorter than minimum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_INVALID.""",

"curPinLongerThanMaxPin": """Test started: P-12 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform change PIN with invalid current PIN which is longer than maximum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_INVALID.""",

"curPinNewPinShorterThanMinPin": """Test started: P-13 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both shorter than the minimum required length, while ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_INVALID.""",

"curPinNewPinLongerThanMaxPin": """Test started: P-14 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both longer than the maximum required length, while ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"newPinShorterThanMinPin_PinNotSet": """Test started: P-15 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt Change PIN , when new PIN is shorter than minimum pin length (i.e. Current PIN is valid but new PIN is invalid), ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"newPinLongerThanMaxPin_PinNotSet": """Test started: P-16 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt Change PIN, when new PIN is longer than maximum pin length (i.e. Current PIN is valid but new PIN is invalid), ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"curPinShorterThanMinPin_PinNotSet": """Test started: P-17 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to perform change PIN with invalid current PIN which is shorter than minimum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"curPinLongerThanMaxPin_PinNotSet": """Test started: P-18 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to perform change PIN with invalid current PIN which is longer than maximum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"curPinNewPinShorterThanMinPin_PinNotSet": """Test started: P-19 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both shorter than the minimum required length, while ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"curPinNewPinLongerThanMaxPin_PinNotSet": """Test started: P-20 :
Precondition: Authenticator must be Reset and has no PIN set.
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both longer than the maximum required length, while ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"newPinWithoutPadding": """Test started: P-21 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation using a correct current PIN with padding and a new PIN without padding(E.g. 8 digit new PIN without padding), while ensuring all other command parameters are correct. The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"changePinBlock": """Test started: P-23 :
Precondition: Authenticator must be reset, has PIN set and set PIN retries counter to 1.
Attempt to perform Change PIN operation with incorrect current PIN, ensuring all remaining command parameters must be correct. The authenticator is expected to return  CTAP2_ERR_PIN_BLOCKED.""",

"block-Set-Change-Verify": """Test started: P-24 :
Precondition: Authenticator is not Reset and PIN must be blocked.
Attempt to perform the change PIN operation using valid PIN values, ensuring all command parameters are correct. The authenticator is expected to return CTAP2_ERR_PIN_BLOCKED. Next, reset the authenticator and set a new PIN using the setPIN (0x03) command, ensuring all parameters are correct; the authenticator should return CTAP2_OK. Then perform the change PIN operation again using a valid current PIN and a valid new PIN, with all parameters correctly provided. The authenticator must return CTAP2_OK. Finally, verify the new changed PIN with credential management operation.""",

"unsupportedProtocolChangePin": """Test started: P-25 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to change a currentPIN, ensuring all command parameters are correct. However, during the changePIN operation, provide an unsupported pinUvAuthProtocol value (for example, 3, when the authenticator only supports protocols 1 and 2). The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"invalidSubCommandChangePin": """Test started: P-26 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to change a currentPIN. However, during the changePIN operation, provide an invalid changePIN subcommand value (for example, 0x0A). The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"missing_newPinEnc_parameter": """Test started: P-27 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform change PIN with correct currentPIN, making sure one of the mandatory command parameter is missing  (e.g., missing newPinEnc, pinHashEnc, pinUvAuthParam, keyAgreement). The authenticator should respond with CTAP2_ERR_MISSING_PARAMETER. """,

"invalidKeyAgreement": """Test started: P-28 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform a change PIN operation using a valid current PIN and a valid new PIN, but construct the request with a corrupted or invalid keyAgreement value. When the authenticator attempts decapsulation, it should fail and return CTAP1_ERR_INVALID_PARAMETER.""",

"invalidHMAC": """Test started: P-29 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform change PIN, ensure all command parameters are correct but send tampered or incorrect pinUvAuthParam(HMAC computed over (newPinEnc || pinHashEnc)). Authenticator computes verification using shared secret and the comparision must fail. Authenticator is expected CTAP2_ERR_PIN_AUTH_INVALID.""",

"incorrectPinHashEnc": """Test started: P-30 :
Precondition: Authenticator must be Reset , has PIN set and pinRetries > 1.
Attempt to perform the change PIN operation by sending an incorrect current PIN hash in pinHashEnc (e.g., using an invalid value in pinHashEnc). The authenticator must detect the mismatch, decrement the pinRetries counter by 1. It should return CTAP2_ERR_PIN_INVALID.""",

"incorrectPinHashEnc3Times": """Test started: P-31 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation by sending an incorrect current PIN hash in pinHashEnc (e.g., an invalid value) for the third consecutive time. The authenticator must return CTAP2_ERR_PIN_AUTH_BLOCKED, indicating that a power cycle is required before further operations. This mechanism ensures that malware on the platform cannot block the device without user involvement.""",

"incorrectNewPinEnc": """Test started: P-32 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation with all command parameters correctly provided, but supply a corrupted (malformed) ciphertext for newPinEnc. When the authenticator attempts to decrypt it, the decryption should fail, and the authenticator must return CTAP2_ERR_PIN_AUTH_INVALID.""",

"newPinEncNotPaddedto64Bytes": """Test started: P-33 :
Precondition: Authenticator must be Reset and has PIN set.
Attempt to perform the change PIN operation with all command parameters correctly provided, but supply a newPinEnc value that decrypts into a paddedNewPin whose length is not 64 bytes. The authenticator must validate the length and return CTAP1_ERR_INVALID_PARAMETER.""",

"forceChangePINisTRUE": """Test started: P-34 :
Precondition: Authenticator must be reset and has PIN set.
Attempt to Change PIN, when forcePINChange is true but newPIN is smiliar to currentPIN. The authenticator must returns
CTAP2_ERR_PIN_POLICY_VIOLATION.

Example:
> Authenticator has a current PIN (example: "123456").
> Authenticator reports: forcePINChange = true (meaning: the user must change PIN).
> The client attempts to set a new PIN that is actually the same as the old one (example: "123456").
> Authenticator compares the first 16 bytes of SHA-256 hash of both PINs.
> Since the hashes match → the PIN did not change.
> The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"forceChangePINisTRUE_2": """Test started: P-35 :
Precondition: Authenticator must be reset and has PIN set.
If forcePINChange is set to true, initiate a PIN Change using the changePIN (0x04) subCommand, ensuring all command parameters are valid. The newPIN must be different from the currentPIN. After the operation, the authenticator should return CTAP2_OK, and the forcePINChange flag must be cleared (set to false).""",

"invalidatePinUvAuthToken": """Test started: P-36 :
Precondition: The authenticator must be reset, have a PIN already set, and a pinUvAuthToken must be obtained before performing the PIN change. Keep this token for subsequent use.
Start by performing a PIN change using the previously acquired pinUvAuthToken and ensuring all command parameters are valid. The authenticator should return CTAP2_OK and must invalidate the pinUvAuthToken.
Next, attempt another PIN change using the same (now invalidated) pinUvAuthToken, while keeping all other command parameters correct. In this case, the authenticator must return an error because token is invalidated.""",


}
    
    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    util.printcolor(util.YELLOW, descriptions[mode])
    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    pin = "123456"

    if reset_required == "yes":
        util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        util.APDUhex("80100000010400", "GetInfo")

    if set_pin_required == "yes":
        pin = "12345678"
        setpin(pin)  #Set new pin 12345678

    
    old_pin = pin

    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------
    if mode == "minimumNewPinLength":
       new_pin = "123456"                             # minimum 6 bytes new PIN

    elif mode == "maximumNewPinLength":
        new_pin = "A" * 63                           # maximum allowed new PIN length

    elif mode == "validNewPinLength":
        new_pin = "123456"                            # any valid New PIN length (6)

    elif mode == "pinlengthLess":
        new_pin = "12"                               # shorter than minimum → invalid

    elif mode == "pinlengthexced":
        new_pin = "A" * 70                           # longer than maximum → invalid

    elif mode == "getPinRetries":
        new_pin = "123456"                             # Get pin retries of valid PIN

    elif mode == "multipleChangePinOperation":
        new_pin = "123456"                             # Change Pin operation multiple times

    elif mode == "randomCurrentPin":
        new_pin = "123456"           
        old_pin = "A6B5C4"                             # Change PIN operation with random current pin without pin Set

    elif mode == "newPinShorterThanMinPin":
        new_pin = "123"                                # Change PIN operation with new PIN shorter than minimum PIN Length

    elif mode == "newPinLongerThanMaxPin":
        new_pin = "A" * 70                             # Change PIN operation with new PIN longer than maximum PIN Length

    elif mode == "curPinShorterThanMinPin":
        new_pin = "123456"                             # Change PIN operation with current PIN shorter than minimum PIN Length
        old_pin = "123"

    elif mode == "curPinLongerThanMaxPin":
        new_pin = "123456"                              # Change PIN operation with current PIN longer than maximum PIN Length
        old_pin = "A" * 70

    elif mode == "curPinNewPinShorterThanMinPin":
        new_pin = "123"                                 # Change PIN operation with current PIN and new PIN both shorter than minimum PIN Length
        old_pin = "123"

    elif mode == "curPinNewPinLongerThanMaxPin":
        new_pin = "A" * 70                              # Change PIN operation with current PIN and new PIN both longer than maximum PIN Length
        old_pin = "A" * 70

    elif mode == "newPinShorterThanMinPin_PinNotSet":
        new_pin = "123"                                # Change PIN operation with new PIN shorter than minimum PIN Length when pin not set

    elif mode == "newPinLongerThanMaxPin_PinNotSet":
        new_pin = "A" * 70                             # Change PIN operation with new PIN longer than maximum PIN Length when pin not set

    elif mode == "curPinShorterThanMinPin_PinNotSet":
        new_pin = "123456"                             # Change PIN operation with current PIN shorter than minimum PIN Length when pin not set
        old_pin = "123"

    elif mode == "curPinLongerThanMaxPin_PinNotSet":
        new_pin = "123456"                              # Change PIN operation with current PIN longer than maximum PIN Length when pin not set
        old_pin = "A" * 70

    elif mode == "curPinNewPinShorterThanMinPin_PinNotSet":
        new_pin = "123"                                 # Change PIN operation with current PIN and new PIN both shorter than minimum PIN Length when pin not set
        old_pin = "123"

    elif mode == "curPinNewPinLongerThanMaxPin_PinNotSet":
        new_pin = "A" * 70                              # Change PIN operation with current PIN and new PIN both longer than maximum PIN Length when pin not set
        old_pin = "A" * 70

    elif mode == "newPinWithoutPadding":
        new_pin = "12345678"                            # Change PIN Operation when new pin is not padded

    # Decrementing retry counts using changepin command by giving incorrect pin
    elif mode == "changePinBlock":
        old_pin = "554432"
        new_pin = "768987"
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        fixRetryCount = getRetryCountInInteger(response)
        util.printcolor(util.YELLOW, f"Total Allowed Retry Counts : {fixRetryCount}")
        retryCount = fixRetryCount

        if fixRetryCount >= 1:
             while retryCount > 1:
                retryCount = wrongPinChangeAndPowerCycle(old_pin, new_pin)
                if retryCount == 1:    
                    util.printcolor(util.REDWHITE, f"Remaining Allowed Retry Counts : {retryCount}... Now Performing Chnage PIN to block")
                    old_pin = "554432"
                    new_pin = "768987"

                elif retryCount == 0:
                    util.printcolor(util.RED, f"PIN is blocked already !")    

                else:
                   util.printcolor(util.YELLOW, f"Remaining Allowed Retry Counts : {retryCount}")
        else:
            util.printcolor(util.RED, f"PIN is blocked already !")

    elif mode == "block-Set-Change-Verify":
        new_pin = "12345678"
        old_pin = "12345678"
        changePINOnly(old_pin, new_pin)
        util.APDUhex("80108000010700", "Reset Card", checkflag=True)  #Reset Card
        util.APDUhex("80100000010400", "GetInfo")
        Setpinp22.setpin(old_pin)  #Set new pin 12345678
    
    elif mode == "unsupportedProtocolChangePin":
        new_pin = "12345678"

    elif mode == "invalidSubCommandChangePin":
        new_pin = "12345678"

    elif mode == "missing_newPinEnc_parameter":
        new_pin = "12345678"

    elif mode == "invalidKeyAgreement":
        new_pin = "12345678"

    elif mode == "invalidHMAC":
        new_pin = "12345678"

    elif mode == "incorrectPinHashEnc":
        new_pin = "12345678"
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        fixRetryCount = getRetryCountInInteger(response)
        if fixRetryCount > 1:
            util.printcolor(util.YELLOW, f"Total Allowed Retry Counts : {fixRetryCount}")
        else:
            util.printcolor(util.RED, f"Test Case aborted in middle remaining Retry Counts is not >= 1, retryCount => {fixRetryCount}")
            return 0
        
    elif mode == "incorrectPinHashEnc3Times":
        new_pin = "12345678"

    elif mode == "incorrectNewPinEnc":
        new_pin = "12345678"

    elif mode == "newPinEncNotPaddedto64Bytes":
        new_pin = "12345678"

    elif mode == "forceChangePINisTRUE":
        new_pin = "12345678"

        util.APDUhex("80100000010400", "Get Info")
        permission = 0x20  # authenticator config
        pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
        subCommand = 0x03
        apdu=authenticatorConfig.newMinPinLength_forcechangePin(pinToken,subCommand)
        response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        util.APDUhex("80100000010400", "Get Info")

    elif mode == "forceChangePINisTRUE_2":
        new_pin = "12345678"
        util.APDUhex("80100000010400", "Get Info")
        permission = 0x20  # authenticator config
        pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
        subCommand = 0x03
        apdu=authenticatorConfig.newMinPinLength_forcechangePin(pinToken,subCommand)
        response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
        util.APDUhex("80100000010400", "Get Info")
        changePINOnly(old_pin, new_pin)
        util.printcolor(util.RED, "First time change Pin with similar pins (old pin and new pin) must be fail")
        new_pin = "123456"
        changePINOnly(old_pin, new_pin)
        util.printcolor(util.YELLOW, "Second time change Pin with different pins (old pin and new pin) must be succeed")
        old_pin = "123456"
        changePINOnly(old_pin, new_pin)
        util.printcolor(util.YELLOW, "Third time change Pin with similar pins (old pin and new pin) must be succeed, hence forceChangePin is set to False again.")

    elif mode == "invalidatePinUvAuthToken":
        new_pin = "123456"
    
    util.printcolor(util.YELLOW, f" Selected new PIN for mode '{mode}': {new_pin}")
    util.printcolor(util.YELLOW, f" Selected current PIN for mode '{mode}': {old_pin}")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)

    if mode == "invalidKeyAgreement":
        key_agreement, sharedSecret = util.wrongencapsulate(decoded_data[1])
    else:
        key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    if mode == "incorrectPinHashEnc":
        oldPinHash = util.sha256(old_pin.encode())[:8]
    elif mode == "incorrectPinHashEnc3Times":
        oldPinHash = util.sha256(old_pin.encode())[:8]
    else:
        oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    if mode ==  "newPinWithoutPadding":
        newPinPadded = util.withoupadded(new_pin)
    elif mode == "newPinEncNotPaddedto64Bytes":
        newPinPadded = util.pad_pin_not_64bytes(new_pin)
    else:
        newPinPadded = util.pad_pin(new_pin)

    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    if mode == "invalidHMAC":
        combined = newPinEnc + pinHashEnc + os.urandom(1)
    else:
        combined = newPinEnc + pinHashEnc

    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    if mode == "invalidatePinUvAuthToken":
        pinAuth2 = pinAuth

    if mode == "unsupportedProtocolChangePin":
        apdu = createCBORchangePIN_protocol3(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    elif mode == "missing_newPinEnc_parameter":
        apdu = createCBORchangePIN_protocol2_missing_newPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    elif mode == "invalidSubCommandChangePin":
        apdu = createCBORchangePIN_protocol2_invalid_subcommand(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    elif mode == "incorrectNewPinEnc":
        apdu = createCBORchangePIN_protocol2_incorrectNewPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    else:
        apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

    if mode == "block-Set-Change-Verify":
        verifyChangePIN("block-Set-Change-Verify",old_pin, RP_domain, user)

    if mode == "getPinRetries":
        util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)

    if mode == "incorrectPinHashEnc":
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        redRetryCount = getRetryCountInInteger(response)
        if redRetryCount == fixRetryCount-1:
             util.printcolor(util.YELLOW, f"Total Allowed Retry Counts reduced by 1, current retry counts remaining : {redRetryCount}")
        else:
            util.printcolor(util.RED, f"Total Allowed Retry Counts not reduced by 1, current retry counts remaining : {redRetryCount}")

    if mode == "incorrectPinHashEnc3Times":
        for i in range(2):
            changePINIncorrectPinHash(old_pin, new_pin)

    if mode == "invalidatePinUvAuthToken":
        old_pin = "123456"
        new_pin = "123456"
        changePINOnlyWithPinAuthToken(old_pin, new_pin, pinAuth2)

    # if mode == "forceChangePINisTRUE":
    #     permission = 0x20  # authenticator config
    #     pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)


def wrongPinChangeAndPowerCycle(curPin, newPin):
    changePINOnly(curPin, new_Pin)
    response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
    pinRetryCount = getRetryCountInInteger(response)
    util.ResetCardPower()
    util.ConnectJavaCard()
    return pinRetryCount

def changePinMultiple(mode, reset_required, set_pin_required):
    i = 1

    if mode == "multipleChangePinOperation" and reset_required == "no" and set_pin_required == "yes":
        i = 2
    elif mode == "multipleChangePinAndVerify" and reset_required == "no" and set_pin_required == "no":
        i = 2
    
    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
        
 "multipleChangePinOperation": """Test started: P-6 :
Precondition: Authenticator must be Reset and has no PIN set.
Begin by attempting the changePIN command when no PIN is set on the authenticator, ensuring all command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET. Next, set a new valid PIN with all parameters correctly specified; the authenticator should return CTAP2_OK. Then, attempt to change the PIN again with correct PIN, ensuring all parameters are correct—this time, the authenticator must return CTAP2_OK. In the same scenario, use the getPINRetries command to verify that the authenticator reports the maximum allowed PIN retry count, as expected.""",


"multipleChangePinAndVerify": """Test started: P-7:
Precondition: The authenticator is reset and a PIN is already set.
Objective: Validate changing the PIN multiple times.
First, change the current PIN to a new valid PIN, ensuring all command parameters are correct. The authenticator should return CTAP2_OK.
Next, change the PIN again to another valid PIN, with all parameters correctly provided. The authenticator should again return CTAP2_OK.
Finally, initiate a protected operation—such as credential management—to verify the most recently updated PIN. Ensure all verification command parameters are correct. The authenticator should return CTAP2_OK.""",

"multipleChangePinAndVerifyPinBlock": """Test started: P-22:
Precondition: The authenticator must be reset and have a PIN configured.
Objective: Verify that the authenticator decrements the pinRetries counter by 1 after each failed attempt.
Attempt to perform the change PIN operation using an incorrect current PIN, ensuring all other command parameters are valid. The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID. Then, use the getPINRetries command to confirm that the retry counter has decreased by exactly one.""",

}
    
    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    if i == 1:
        util.printcolor(util.YELLOW, descriptions[mode])

    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    pin = "123456"

    if reset_required == "yes":
        util.APDUhex("80108000010700", "Reset Card", checkflag=True)  #Reset Card
        util.APDUhex("80100000010400", "GetInfo")
    
    if set_pin_required == "yes":
        pin = "12345678"
        Setpinp22.setpin(pin)  #Set new pin 12345678

    old_pin = pin

    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------
    if mode == "multipleChangePinOperation":
        new_pin = "123456"                             # Change Pin operation multiple times

    if mode == "multipleChangePinAndVerify":
        new_pin = "123456"                             # Change Pin operation multiple times

    if mode == "multipleChangePinAndVerifyPinBlock":
        new_pin = "123456"                             # Change PIN operation untill pin block

    util.printcolor(util.YELLOW, f" Selected new PIN for mode '{mode}': {new_pin}")
    util.printcolor(util.YELLOW, f" Selected current PIN for mode '{mode}': {old_pin}")
    
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    if mode != "multipleChangePinAndVerifyPinBlock":
        #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
        cardPublicKeyHex, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

        cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
        decoded_data = cbor2.loads(cbor_bytes)
        key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

        oldPinHash = util.sha256(old_pin.encode())[:16]
        pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

        newPinPadded = util.pad_pin(new_pin)
        newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

        #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
        combined = newPinEnc + pinHashEnc
        hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
        pinAuth = hmac_value[:32]


        apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
        util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

    if mode == "multipleChangePinOperation":
        if i == 1:
            i = 2
            changePinMultiple("multipleChangePinOperation","no","yes")
        elif i == 2:
            util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)

    elif mode == "multipleChangePinAndVerify":   
        if i == 1:
            i == 2
            changePinMultiple("multipleChangePinAndVerify","no","no")
            verifyChangePIN("multipleChangePinAndVerify",curpin,RP_domain,user) 

    elif mode == "getPinRetries":
        util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
    
    elif mode == "multipleChangePinAndVerifyPinBlock":
        old_pin = "132457"
        new_pin = "123456"
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        retryCount = getRetryCountInInteger(response)
        util.printcolor(util.YELLOW, f"Total Allowed Retry Counts : {retryCount}")
        if retryCount != 0:
            for i in range(2):
                changePINOnly(old_pin, new_pin)
                response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
                retryCount = getRetryCountInInteger(response)                
                util.printcolor(util.RED, f"Remaining Retry Attempts : '{retryCount}'")
        else:
            util.printcolor(util.RED,"X---X--- Test Case Not Performed PIN is already BLOCKED ---X---X")

def getRetryCountInInteger(response):
    last_byte = response[-2:] 
    value = int(last_byte, 16)
    return value



def authenticatorClientPin():
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getKeyAgreement(0x02) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "keyAgreement" field, and its of type MAP
            (b) in COSE "keyAgreement" field:
                (1) check that public key is EC2(kty(1) is set to 2) 
                (2) check that key crv(-1) curve field that is set to P256(1)
                (3) check that key alg(3) is set to ECDH-ES+HKDF-256(-25)
                (4) check that key contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) check that key contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (6) check that key does NOT contains ANY other coefficients""");

    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
    util.APDUhex("00a4040008a0000006472f0001","Select applet") 
    util.APDUhex("80108000010700","Reset Card PIN")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")                                      
    util.APDUhex("801000000606a20101020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    util.ResetCardPower()
    util.ConnectJavaCard()
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80108000010700","Reset Card PIN")
    


# --- Utility Functions ---
def int2bytes(val, length):
    return val.to_bytes(length, 'big')

def bytes2int(b):
    return int.from_bytes(b, 'big')

def pad_pin1(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')
    if len(pin_bytes) < 6:
        raise ValueError("PIN must be at least 6 bytes")
    if len(pin_bytes) > 64:
        raise ValueError("PIN must not exceed 64 bytes")
    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    if validate:
        if len(pin_bytes) < 6:
            raise ValueError("PIN must be at least 6 bytes")
        if len(pin_bytes) > 64:
            raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes













def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 1,   # crv: P-256
        -2: int2bytes(pub.x, 32),
        -3: int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

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
    apdu = "80100000" + format(length, '02X') + "06" + data_cbor
    return apdu

# --- Main Function ---
def set_client_pin_protocol1(pin: str):
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1
         Generate a shared key by deriving sharedSecret from previously obtained keyAgreement, and set new random clientPin.""");
    setpin(pin)

def setpin(pin):

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    util.APDUhex("80100000010700", "Reset Card PIN (optional)")
    util.APDUhex("00a4040008a0000006472f0001", "Re-select Applet")
    util.APDUhex("80100000010400", "GetInfo")

    # Step 1: Get peer (authenticator) key agreement
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    key_agreement, shared_secret = encapsulate_protocol1(decoded[1])
    padded_pin = pad_pin(pin, validate=False)  # skips min length check
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)

    # Compute HMAC using same 32 bytes
    auth = hmac_sha256(shared_secret, new_pin_enc)
    pin_auth = auth[:16]  # only first 16 bytes
    
    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response, status
    # util.APDUhex("80100000010400", "GetInfo after SetPIN")


def createCBORchangePIN_protocol1(pinHashEnc, newPINenc, pinAuth, keyAgreement):
    """
    Constructs a CBOR-encoded APDU command for ClientPIN ChangePIN (subCommand = 0x04)
    """
    cbor_map = {
        1: 1,               # pinProtocol = 1
        2: 4,               # subCommand = 0x04 (change PIN)
        3: keyAgreement,    # keyAgreement (MAP)
        4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
        5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
        6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
    }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu


def change_client_pin_protocol1(current_pin: str, new_pin: str):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-2
        Change current pincode to the new pincode""")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin = pad_pin(new_pin)
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

def get_pin_token_protocol1(pin: str) -> bytes:
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW, "****ClientPin protocol 1 ****")
    util.printcolor(util.YELLOW, """""Test started: P-3
        Get a valid pinAuth token""")
    getPINtokenPubkey(pin)

def getPINtokenPubkey(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)
    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token



def aes256_cbc_decrypt(shared_secret: bytes, encrypted: bytes) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()
   #make credential
def RegisterUser(pin, username, display, rp):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-4
        Send a valid CTAP2 authenticatorMakeCredential(0x01) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""")
    hashchallenge = os.urandom(32);
    result = makeCred(pin, hashchallenge, rp, username)
    return result

def makeCred(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
       
    pinToken = getPINtokenPubkey(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCred(clientDataHash, rp, user, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result 
   
def createCBORmakeCred(clientDataHash, rp, user, pinAuthToken):

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

    option  = {"rk": False}

    extension={"credProtect": 1, 
                "hmac-secret": True}

    cbor_hash          = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp            = cbor2.dumps(PublicKeyCredentialRpEntity).hex().upper()
    cbor_user          = cbor2.dumps(PublicKeyCredentialUserEntity).hex().upper()
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()
    credParam          = cbor2.dumps(pubKeyCredParams).hex().upper()
    rk                 = cbor2.dumps(option).hex().upper()

    ex                = cbor2.dumps(extension).hex().upper()

    dataCBOR = "A8"
    dataCBOR = dataCBOR + "01"+ cbor_hash
    dataCBOR = dataCBOR + "02"+ cbor_rp
    dataCBOR = dataCBOR + "03"+ cbor_user
    dataCBOR = dataCBOR + "04"+ credParam
    dataCBOR = dataCBOR + "07" + rk

    dataCBOR = dataCBOR + "06" + ex

    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand


def getAsseration(pin, username, rp,response):
    util.printcolor(util.YELLOW,"")
    credId =getasserationrequest.authParasing(response)
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, """Test started: P-5
        Send a valid CTAP2 authenticatorGetAssertion(0x02) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.
        Check that authData.flags have UV flag set.""")
    hashchallenge = os.urandom(32);
    result = authenticateUser(pin, hashchallenge, rp, credId)
    return result

def authenticateUser(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken = getPINtokenPubkey(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertion(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result


def createCBORmakeAssertion(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]


    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "01"                                        # 0x07: pinProtocol = 1

    # 5-element map
    dataCBOR = "A5"
    dataCBOR += "01" + cbor_rp
    dataCBOR += "02" + cbor_hash
    dataCBOR += "03" + cbor_allowlist
    dataCBOR += "06" + cbor_pinAuthToken
    dataCBOR += "07" + pin_protocol

    #util.printcolor(util.BLUE, dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    full_payload = "02" + dataCBOR
    length = len(full_payload) // 2
    apdu = "80108000" + format(length, '02X') + full_payload
    return apdu


def test_setpin_length_between_min_and_63(base_pin="A"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW, "Test started: P-1")
    util.printcolor(util.YELLOW,
        "Try setting new pin that is of size between minPINLength+1 and 63 characters. "
        "Expect Authenticator to return CTAP1_ERR_SUCCESS (0x00)"
    )

    
    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("80100000010400", "GetInfo")
    if status != 0x9000:
        raise Exception("GetInfo failed")

    
    decoded = cbor2.loads(binascii.unhexlify(response[2:]))
    min_pin_len = decoded.get(0x03)  

    if isinstance(min_pin_len, bytes):
        min_pin_len = int.from_bytes(min_pin_len, 'big')

    if not isinstance(min_pin_len, int) or min_pin_len < 4 or min_pin_len > 63:
        min_pin_len = 4 

    test_pin_length = min_pin_len + 1
    if test_pin_length > 63:
        test_pin_length = 63  
   
    test_pin = (base_pin * test_pin_length)[:test_pin_length]

    
    try:
        setpin(test_pin)
        util.printcolor(util.GREEN, f"✅ Test passed: PIN of length {test_pin_length} accepted")
    except Exception as e:
        util.printcolor(util.RED, f"❌ Test failed: {str(e)}")





def test_setpin_less_than_4_bytes_raw1(pin="123"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: f-1
        Try setting new pin, that is less than 4 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION (0x37).""");

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801080000606a20101020200", "GetKeyAgreement")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_cose_key = decoded[1]
    
    key_agreement, shared_secret = encapsulate_protocol1(peer_cose_key)   
    padded_pin = pad_pin2(pin, validate=False)  # allow < 4 byte PIN for test
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)
    pin_auth = hmac_sha256(shared_secret, new_pin_enc)[:16]   

    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)   
    response, status = util.APDUhex(apdu, "Set PIN with short PIN", checkflag=False)
    print(f"<--- DATA RECEIVED: {hex(status)[2:].upper()}")


def test_setpin_more_than_63_bytes_raw(pin="111111111111111111111111111111111111111111111111111111111111111111"):
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: f-2
         Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION (0x37)""");

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801080000606a20101020200", "GetKeyAgreement")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_cose_key = decoded[1]
    
    key_agreement, shared_secret = encapsulate_protocol1(peer_cose_key)   
    padded_pin = pad_pin2(pin, validate=False)  # allow < 4 byte PIN for test
    new_pin_enc = aes256_cbc_encrypt(shared_secret, padded_pin)
    pin_auth = hmac_sha256(shared_secret, new_pin_enc)[:16]   

    apdu = create_cbor_setpin_protocol1(new_pin_enc, pin_auth, key_agreement)   
    response, status = util.APDUhex(apdu, "Set PIN with short PIN", checkflag=False)
    print(f"<--- DATA RECEIVED: {hex(status)[2:].upper()}")

def retriesCount():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-1             
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "retries" field
            (b) authenticatorClientPin_Response.retries is of type NUMBER
            (c) authenticatorClientPin_Response.retries is max of 8!""" )
    pinRetriescount()      
                              
def pinRetriescount():
    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")
    response, status = util.APDUhex("801000000606a20101020100", "GetRetries")

    assert status == 0x9000, "Expected status 0x9000 for GetRetries"
#   Parse response
    cbor_data = binascii.unhexlify(response[2:])  # skip 00 prefix
    decoded = cbor2.loads(cbor_data)

    assert 3 in decoded, "Missing 'retries' key in response"
    assert isinstance(decoded[3], int), "'retries' is not an integer"
    assert 0 <= decoded[3] <= 8, f"'retries' out of range: {decoded[3]}"

    util.printcolor(util.GREEN, f"Retries: {decoded[3]} (valid)")
    


def piAuthBlocked():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-2
        Send two CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that each request fails with error CTAP2_ERR_PIN_INVALID(0x31)
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, and check that retries have decreased by two
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED(0x34)"""                                     );

    util.APDUhex("00a4040008a0000006472f0001", "Select Applet")

    response, status = util.APDUhex("801000000606a20101020100", "GetRetries")

    assert status == 0x9000, "Expected status 0x9000 for GetRetries"
#   Parse response
    cbor_data = binascii.unhexlify(response[2:])  # skip 00 prefix
    decoded = cbor2.loads(cbor_data)

    assert 3 in decoded, "Missing 'retries' key in response"
    assert isinstance(decoded[3], int), "'retries' is not an integer"
    assert 0 <= decoded[3] <= 8, f"'retries' out of range: {decoded[3]}"

    util.printcolor(util.GREEN, f"Retries: {decoded[3]} (valid)")
    

def pinTokenBlocked():
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"")
    util.printcolor(util.YELLOW,"****ClientPin protocol 1****")
    util.printcolor(util.YELLOW,"""Test started: P-3
        Register a valid authenticatorMakeCred(0x01) using the valid PIN. Check that retries counter is reset and back to the original retries counter.
        Keep sending getPINToken with invalid pin until retries counter is 0.
        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains valid pinCode, and check that authenticator returns error CTAP2_ERR_PIN_BLOCKED(0x32).""")
 



def pad_pin2(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    if validate:
        if len(pin_bytes) < 4:
            raise ValueError("PIN must be at least 4 bytes")
        if len(pin_bytes) > 64:
            raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')


def getPINtoken(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
   
    response, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)

    
    cbor_map = {
        1: 1,                  # pinProtocol = 1
        2: 5,                  # subCommand = 0x05 (getPINToken)
        3: key_agreement,      # keyAgreement (MAP)
        6: pinHashEnc          # pinHashEnc
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x05 GetPINToken", checkflag=True)

def checkRetriesCount(pin,retries):

   for i in range(retries):
    print(f"\n--- Attempt {i + 1} ---")

    try:
        util.ResetCardPower()
        util.ConnectJavaCard()

        # Attempt to get PIN token with wrong PIN
        response =getPINtoken(pin)
        print("Response:", response)
    except Exception as e:
        print(f"getPINtoken() Exception: {e}")

    try:
        retry_count = pinRetriescount()
        print(f"Remaining PIN retries: {retry_count}")
        if retry_count == 0:
            print("PIN is blocked (CTAP2_ERR_PIN_AUTH_BLOCKED). Stopping test.")
            break
    except Exception as e:
        print(f"retriesCount() Exception: {e}")