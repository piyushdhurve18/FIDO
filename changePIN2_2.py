import util
import binascii
import cbor2
import Setpinp22
import credentialManagement
import authenticatorConfig
import os
from textwrap import wrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, hmac

import clientprotocol2
import clientprotocol1
import DocumentCreation

RP_domain = "localhost"
curpin="12121212"
user="bobsmith"
new_Pin = ""
clientDataHash = os.urandom(32)
SUMMARY_TABLE = DocumentCreation.SUMMARY_TABLE
DETAILED_TABLE = DocumentCreation.DETAILED_TABLE
PROTOCOL = 2
COMMAND_NAME = "CHANGE PIN"
PASS = "PASS"
FAIL = "FAIL"
passCount = 0
failCount = 0
scenarioCount = 0

def changePin(mode, reset_required, set_pin_required,protocol):
    global passCount
    global failCount
    global scenarioCount
    global COMMAND_NAME
    global PROTOCOL
    # ------------------------------
    #  MODE → TEST DESCRIPTION
    # ------------------------------
    descriptions = {
        "minimumNewPinLength": """Test started: P-1 :
        Precondition: The authenticator must be reset and must already have a PIN configured.;
        Step: Change the existing PIN to a new valid PIN that meets the minimum allowed length, ensuring all command parameters are correct.;
        Expected Result:The authenticator returns CTAP2_OK.""",

        "maximumNewPinLength": """Test started: P-2 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Step:Change the existing PIN to a new valid PIN that meets the maximum allowed length, ensuring all command parameters are correct.;
Expected Result:The authenticator returns CTAP2_OK.""",

        "validNewPinLength": """Test started: P-3 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Step: Change the existing PIN to a new valid PIN with a random length between the minimum and maximum allowed lengths, ensuring all command parameters are correct.;
Expected Result: The authenticator returns CTAP2_OK.""",

        "protectedOperation": """Test started: P-4 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Step 1: Change the existing PIN to a new valid PIN, ensuring all command parameters are correct.;
Step 2: Initiate a protected operation—registration (makeCredential) then  authentication (getAssertion)—to verify the newly updated PIN. Ensure that all parameters in the PIN verification command are correct.;
Expected Result: The authenticator returns CTAP2_OK.""",

"getPinRetries": """Test started: P-5 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Step 1:Change the existing PIN to a new valid PIN, ensuring all command parameters are correct.;
Step 2:Use the getPINRetries command with correct parameters to retrieve the current retry count.;
Expected Result:The authenticator returns the maximum allowed PIN retry count.""",

 "notSet-ChangeFail-Set-Change-RetryCount": """Test started: P-6 :
Precondition: The authenticator must be reset and must not have any PIN set.;
Step 1:Attempt to execute the changePIN command while no PIN is set on the authenticator, ensuring all command parameters are correct.;
Expected Result: The authenticator returns CTAP2_ERR_PIN_NOT_SET.;
Step 2:Set a new valid PIN, providing all required parameters correctly.;
Expected Result: The authenticator returns CTAP2_OK.;
Step 3:Attempt to change the PIN again, this time using the correct existing PIN and providing all command parameters correctly.;
Expected Result: The authenticator returns CTAP2_OK.;
Step 4:Use the getPINRetries command with correct parameters to retrieve the current retry count.;
Expected Result: The authenticator reports the maximum allowed PIN retry count.""",

"set-Change-Change-Verify": """Test started: P-7 :
Precondition: The authenticator is reset and already has a PIN configured.;
Objective: Validate that the authenticator correctly supports multiple successive PIN changes.;
Step 1:Change the current PIN to a new valid PIN, ensuring all command parameters are correct.;
Expected Result: The authenticator returns CTAP2_OK.;
Step 2:Change the PIN again to another valid PIN, with all parameters correctly provided.;
Expected Result: The authenticator again returns CTAP2_OK.;
Step 3:Initiate a protected operation—such as credential management, makeCredential, or getAssertion—to verify the most recently updated PIN. Ensure all parameters for PIN verification are correct.;
Expected Result: The authenticator returns CTAP2_OK.""",


"randomCurrentPin": """Test started: P-8 :
Precondition: The authenticator is reset and a PIN is not Set.;
Step:Attempt to change a randomly chosen valid PIN (treated as if it were the current PIN) to a new valid PIN, ensuring all other command parameters are correctly provided.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_NOT_SET.""",

"newPinShorterThanMinPin": """Test started: P-9 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to change the PIN using a valid current PIN, but provide a new PIN that is shorter than the minimum allowed PIN length, ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"newPinLongerThanMaxPin": """Test started: P-10 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to change the PIN using a valid current PIN, but provide a new PIN that exceeds the maximum allowed PIN length, ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"curPinShorterThanMinPin": """Test started: P-11 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to change the PIN using an invalid current PIN that is shorter than the minimum allowed PIN length, while providing a valid new PIN and ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_INVALID.""",

"curPinLongerThanMaxPin": """Test started: P-12 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to change the PIN using an invalid current PIN that is longer than allowed PIN length, while providing a valid new PIN and ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_INVALID.""",

"curPinNewPinShorterThanMinPin": """Test started: P-13 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, both of which are shorter than the minimum required PIN length, while ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_INVALID.""",

"curPinNewPinLongerThanMaxPin": """Test started: P-14 :
Precondition: Authenticator must be Reset and has PIN set.;
Step:Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, both of which are longer than the maximum allowed PIN length, while ensuring all other command parameters are correct.;
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER.""",

"newPinShorterThanMinPin_PinNotSet": """Test started: P-15 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt Change PIN , when new PIN is shorter than minimum pin length (i.e. Current PIN is valid but new PIN is invalid),  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET.""",

"newPinLongerThanMaxPin_PinNotSet": """Test started: P-16 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt Change PIN, when new PIN is longer than maximum pin length (i.e. Current PIN is valid but new PIN is invalid),  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET.""",

"curPinShorterThanMinPin_PinNotSet": """Test started: P-17 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt to perform change PIN with invalid current PIN which is shorter than minimum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET.""",

"curPinLongerThanMaxPin_PinNotSet": """Test started: P-18 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt to perform change PIN with invalid current PIN which is longer than maximum pin length and valid new PIN,  ensuring all other command parameters are correct. The authenticator should return CTAP2_ERR_PIN_NOT_SET.""",

"curPinNewPinShorterThanMinPin_PinNotSet": """Test started: P-19 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both shorter than the minimum required length, while ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"curPinNewPinLongerThanMaxPin_PinNotSet": """Test started: P-20 :
Precondition: Authenticator must be Reset and has no PIN set.;
Attempt to perform the change PIN operation using an invalid current PIN and a new PIN, that are both longer than the maximum required length, while ensuring all other command parameters are correct. The authenticator should return  CTAP2_ERR_PIN_NOT_SET.""",

"newPinWithoutPadding": """Test started: P-21 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform the change PIN operation using a correct current PIN with padding and a new PIN without padding(E.g. 8 digit new PIN without padding), while ensuring all other command parameters are correct. The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"reducePINRetriesCount": """Test started: P-22 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Objective: Verify that the authenticator decrements the pinRetries counter by exactly one after each failed PIN attempt.;
Step 1:Attempt to perform the change PIN operation using an incorrect current PIN (pinHashEnc), while ensuring all other command parameters are valid.;
Expected Result: The authenticator returns CTAP2_ERR_PIN_INVALID.;
Step 2:Use the getPINRetries command with correct parameters to retrieve the current retry count.;
Expected Result:The authenticator reports a pinRetries value decreased by exactly one compared to the maximum allowed retries.""",

"multipleChangePinBlock": """Test started: P-23 :
Precondition: Authenticator must be reset, has PIN set.;
Attempt to perform Change PIN operation with incorrect current PIN, ensuring all remaining command parameters must be correct. The authenticator is expected to return  CTAP2_ERR_PIN_BLOCKED.

Precondition: The authenticator has been reset and a PIN is configured.;
Steps:;
1. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_INVALID.;
2. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_INVALID.;
3. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
4. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
5. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must not decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.  again 8 times times.;
6. Then execute the getPinRetries command to retrieve the current retry count should be same as step 4  (denoted as ‘XX’).;
7. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count ‘XX’ as step 4  (denoted as ‘XX’).;
8.Perform again Change PIN  with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
9. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
10. Perform Change PIN  with an incorrect curr PIN with again 8 times times.;
11. Then execute the getPinRetries command to retrieve the current retry count should be same as step 9  (denoted as ‘YY’).;
12 After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count YY as step 9.;
13. Perform change with an incorrect PIN with again 1 times times then authenticator should return  CTAP2_ERR_PIN_INVALID (0x31).; 
14. Then execute the getPinRetries command to retrieve the current retry count should be 1.;
15.  Perform change with an incorrect PIN and expect CTAP2_ERR_PIN_BLOCKED""",

"multipleIncorrectChangePin_LastCorrectChangePIN": """Test started: P-24 :
Precondition: The authenticator has been reset and a PIN is configured.;
Steps:;
1. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_INVALID.;
2. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_INVALID.;
3. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
4. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘XX’).;
5. Attempt to perform the Change PIN operation using an incorrect current PIN , ensuring all remaining command parameters are correct. — the authenticator must not decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.  again 8 times times.;
6. Then execute the getPinRetries command to retrieve the current retry count should be same as step 4  (denoted as ‘XX’).;
7. After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count ‘XX’ as step 4  (denoted as ‘XX’).;
8.Perform again Change PIN  with an incorrect PIN three consecutive times — the authenticator must decrement the retry count and return CTAP2_ERR_PIN_AUTH_BLOCKED.;
9. Then execute the getPinRetries command to retrieve the current retry count (denoted as ‘YY’).;
10. Perform Change PIN  with an incorrect curr PIN with again 8 times times.;
11. Then execute the getPinRetries command to retrieve the current retry count should be same as step 9  (denoted as ‘YY’).;
12 After performing a power-cycle reset, retrieve the PIN retry count again; the authenticator must return the same retry count YY as step 9.;
13. Perform change with an incorrect PIN with again 1 times times then authenticator should return  CTAP2_ERR_PIN_INVALID (0x31).; 
14. Then execute the getPinRetries command to retrieve the current retry count should be 1.;
15.  Perform change with an correct PIN and all other parameter correct and expect CTAP2_OK.;
16. Then execute the getPinRetries command to retrieve the current retry count should be Max (8).""",

"unsupportedProtocolChangePin": """Test started: P-25 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to change a currentPIN, ensuring all command parameters are correct. However, during the changePIN operation, provide an unsupported pinUvAuthProtocol value (for example, 3, when the authenticator only supports protocols 1 and 2). The authenticator should return CTAP1_ERR_INVALID_PARAMETER.""",

"invalidSubCommandChangePin": """Test started: P-26 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to change a currentPIN. However, during the changePIN operation, provide an invalid changePIN subcommand value (for example, 0x0A). The authenticator should return CTAP2_ERR_INVALID_SUBCOMMAND.""",

"missingMandatoryParameters": """Test started: P-27 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform change PIN with correct currentPIN, making sure one of the mandatory command parameter is missing  (e.g., missing newPinEnc, pinHashEnc, pinUvAuthParam, keyAgreement). The authenticator should respond with CTAP2_ERR_MISSING_PARAMETER.;

Case 1: Missing pinUvAuthProtocol;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.;

Case 2: Missing subCommand;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.;

Case 3: Missing keyAgreement;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.;

Case 4: Missing pinHashEnc;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.;

Case 5: Missing newPinEnc;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.;

Case 6: Missing pinUvAuthParam;
Expected Result:The authenticator returns CTAP2_ERR_MISSING_PARAMETER.""",

"invalidKeyAgreement": """Test started: P-28 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform a change PIN operation using a valid current PIN and a valid new PIN, but construct the request with a corrupted or invalid keyAgreement value. When the authenticator attempts decapsulation, it should fail and return CTAP1_ERR_INVALID_PARAMETER.""",


"invalidParametersForChangePIN": """Test started: P-29 :
Precondition (for all cases):
Reset the authenticator.
Ensure that correct PIN is set on the authenticator.
Establish a shared secret with the authenticator and select pinUvAuthProtocol.
Generate the keyAgreement key pair on the platform side.
Prepare a valid changePIN (0x04) request with all fields initially correct:
pinUvAuthProtocol
subCommand = changePIN (0x04)
keyAgreement
pinHashEnc
newPinEnc
pinUvAuthParam
Then, for each negative test below, invalid exactly one parameter expect output as per invalid data.;

Case 1: Invalid pinUvAuthProtocol data and other parameter data should correct/valid;
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER;

Case 2: Invalid subCommand changePIN (0x04)  and other parameter data should correct/valid;
Expected Result:The authenticator returns CTAP2_ERR_INVALID_SUBCOMMAND;

Case 3: Invalid/alter some keyAgreement data and other parameter data should correct/valid;
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER;

Case 4: Invalid/alter some bytes pinHashEnc  and other parameter data should correct/valid;
Expected Result:The authenticator return CTAP2_ERR_PIN_INVALID;

Case 5: Invalid/alter some bytes newPinEnc and other parameter data should correct/valid;
Expected Result:The authenticator returns CTAP1_ERR_INVALID_PARAMETER;

Case 6: Invalid/alter some bytes pinUvAuthParam and other parameter data should correct/valid calculated;
Expected Result:The authenticator returns CTAP2_ERR_PIN_AUTH_INVALID""",



"incorrectPINHashEnc": """Test started: P-30 :
Precondition: Authenticator must be Reset , has PIN set and pinRetries > 1.;
Attempt to perform the change PIN operation by sending an incorrect current PIN hash in pinHashEnc (e.g., using an invalid value in pinHashEnc). The authenticator must detect the mismatch, decrement the pinRetries counter by 1. It should return CTAP2_ERR_PIN_INVALID.""",

"incorrectPinHashEnc3Times": """Test started: P-31 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform the change PIN operation by sending an incorrect current PIN hash in pinHashEnc (e.g., an invalid value) for the third consecutive time. The authenticator must return CTAP2_ERR_PIN_AUTH_BLOCKED, indicating that a power cycle is required before further operations. This mechanism ensures that malware on the platform cannot block the device without user involvement.""",

"malformedNewPINEnc": """Test started: P-32 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform the change PIN operation with all command parameters correctly provided, but supply a corrupted (malformed) ciphertext for newPinEnc. When the authenticator attempts to decrypt it, the decryption should fail, and the authenticator must return CTAP2_ERR_PIN_AUTH_INVALID.""",

"newPinEncNotPaddedto64Bytes": """Test started: P-33 :
Precondition: Authenticator must be Reset and has PIN set.;
Attempt to perform the change PIN operation with all command parameters correctly provided, but supply a newPinEnc value that decrypts into a paddedNewPin whose length is not 64 bytes. The authenticator must validate the length and return CTAP1_ERR_INVALID_PARAMETER.""",

"forceChangePINisTRUE": """Test started: P-34 :
Precondition: Authenticator must be reset, PIN is set  and forcePINChange should be true.;
Attempt to Change PIN, when forcePINChange is true but newPIN is smiliar to currentPIN. The authenticator must returns CTAP2_ERR_PIN_POLICY_VIOLATION.;

Example:;
> Authenticator has a current PIN (example: "123456").
> Authenticator reports: forcePINChange = true (meaning: the user must change PIN).
> The client attempts to set a new PIN that is actually the same as the old one (example: "123456").
> Authenticator compares the first 16 bytes of SHA-256 hash of both PINs.
> Since the hashes match → the PIN did not change.
> The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.""",

"forceChangePINisTRUEWithDifferentPIN": """Test started: P-35 :
Precondition: Authenticator must be reset and has PIN set.;
If forcePINChange is set to true, initiate a PIN Change using the changePIN (0x04) subCommand, ensuring all command parameters are valid. The newPIN must be different from the currentPIN. After the operation, the authenticator should return CTAP2_OK, and the forcePINChange flag must be cleared (set to false).""",

"invalidatePinUvAuthToken": """Test started: P-36 :
Precondition: The authenticator must be reset, have a PIN already set, and a pinUvAuthToken must be obtained before performing the PIN change. Keep this token for subsequent use.;
Start by performing a PIN change using the previously acquired pinUvAuthToken and ensuring all command parameters are valid. The authenticator should return CTAP2_OK and must invalidate the pinUvAuthToken.
Next, attempt another PIN change using the same (now invalidated) pinUvAuthToken, while keeping all other command parameters correct. In this case, the authenticator must return an error because token is invalidated.""",


"invalidatePinUvAuthTokenWithSamePIN": """Test started: P-37 :
Precondition: The authenticator must be reset, have a PIN already set, and a pinUvAuthToken must be obtained before performing the PIN change. Keep this token for subsequent use.;
Start by performing a PIN change using the previously acquired pinUvAuthToken and with  new pin as current PIN and ensuring all command parameters are valid. The authenticator should return CTAP2_OK and must invalidate the pinUvAuthToken.
Next, attempt another PIN change using the same (now invalidated) pinUvAuthToken, while keeping all other command parameters correct. In this case, the authenticator must return an CTAP2_ERR_PIN_AUTH_INVALID because token is invalidated.""",


"forceMinimumNewPinLengthChangePIN": """Test started: P-38 :
Precondition: The authenticator must be reset. A PIN must already be set. The minPINLength value returned by getInfo is noted (this is the current minimum PIN length enforced by the authenticator).;
Step 1:Update the minPINLength to a value greater than the current minimum length obtained from getInfo, using the authenticatorConfig (authConfig) command.;
Step 2:Attempt to change the PIN using a new PIN whose length is equal to the original (old) minPINLength noted in the precondition, while providing all required parameters correctly.;
Expected Result:The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION, because the new PIN length no longer meets the updated (higher) minimum PIN length requirement.""",


"forceMinimumNewPinLengthChangePIN_ValidCase": """Test started: P-39 :
Precondition: The authenticator must be reset. A PIN must already be set. The minPINLength value returned by getInfo is noted (this is the current minimum PIN length enforced by the authenticator).;
Step 1: Increase the minPINLength to a value greater than the original minimum length using the authenticatorConfig (authConfig) command.;
Expected Result: The authenticator updates the configuration successfully and returns CTAP2_OK.;
Step2: Step 2:Change the PIN using a new PIN whose length meets or exceeds the updated minPINLength, ensuring all command parameters are correct.;
Expected Result:The authenticator accepts the new PIN and returns CTAP2_OK.""",


"newAlphanumericPIN": """Test started: P-40 :
Precondition: The authenticator must be reset and must already have a PIN configured.;
Step:Change the existing PIN to a new valid alphanumeric PIN, ensuring all command parameters are correct.;
Expected Result:The authenticator accepts the new alphanumeric PIN and returns CTAP2_OK.""",

"nonZeroPadding": """Test started: P-41 :
Precondition :  The authenticator must be reset and have a PIN configured.;
Execute the Change PIN operation with all parameters valid except for an incorrectly padded NewPin, where some padding bytes contain non-zero values. The authenticator should detect this invalid padding and return CTAP2_ERR_PIN_POLICY_VIOLATION.;
E.g.: abcd123d000000000shhd0000 """,


"protocolMismatch": """Test started: P-42 :
Precondition: The authenticator must be reset and have a PIN configured.;
Attempt to obtain the Key Agreement and Shared Secret using Protocol 1. Then perform a Change PIN operation using Protocol 2 with the generated shared secret, ensuring all parameters are valid. The authenticator should return CTAP2_ERR_PIN_AUTH_INVALID.;
> Repeat the test with the protocols swapped.""",

"checkRetryCountsForDifferentStatusCode": """Test started: P-43 :
Precondition: The authenticator must be reset and have a PIN configured.;
Perform a Change PIN operation, ensuring all parameters are valid but newPIN is shorter than  current minimum PIN length. 
The authenticator should return CTAP2_ERR_PIN_POLICY_VIOLATION. Perform this multiple times and check the retry counts are not reducing evrytime.(i.e. PIN Retry counts must not change)""",


}
    
    if mode not in descriptions:
        raise ValueError("Invalid mode!")

    SCENARIO = util.extract_scenario(descriptions[mode])
    util.printcolor(util.YELLOW, descriptions[mode])
    util.ResetCardPower()
    util.ConnectJavaCard()

    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    # util.APDUhex("80100000010400", "GetInfo")
    pin = "12121212"

    if reset_required == "yes":
        util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
        # util.APDUhex("80100000010400", "GetInfo")

    if set_pin_required == "yes":
        pin = "12121212"
        if protocol == "PROTOCOL_ONE":
            setpinProtocol1(pin)  #Set new pin 12345678
        elif protocol == "PROTOCOL_TWO":
            setpinProtocol2(pin)  #Set new pin 12345678

    util.APDUhex("80100000010400", "GetInfo")

    
    old_pin = pin

    if protocol == "PROTOCOL_ONE":
        PROTOCOL = 1
    else:
        PROTOCOL = 2

    # ------------------------------
    #  MODE → PIN VALUE
    # ------------------------------
    if mode == "minimumNewPinLength":
        scenarioCount += 1
        new_pin = "12345687"  # minimum 6 bytes new PIN
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin,new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin,new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                         
        if status == "00":
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
        else:
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1 


    elif mode == "maximumNewPinLength":
        scenarioCount += 1
        new_pin = "A" * 63                           # maximum allowed new PIN length
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)

        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)

        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1             
       


    elif mode == "validNewPinLength":
        scenarioCount += 1
        new_pin = "12345689012345678901234567890"                            # any valid New PIN length between minimum and maximum pin length
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)

        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)

        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1              
        


    elif mode == "protectedOperation":
        scenarioCount += 1
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
            util.printcolor(util.GREEN,f"CHANGE PIN DONE BY '{protocol}'")
            response, status  = makeCredProtocol1(new_pin,clientDataHash, RP_domain,user)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
            util.printcolor(util.GREEN,f"MAKE CRED DONE BY '{protocol}'")
            response, status = getAsserationProtocol1(new_pin, clientDataHash, RP_domain, response)
            util.printcolor(util.GREEN,f"GET ASSERTION DONE BY '{protocol}'")
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)

        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin,new_pin)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
            util.printcolor(util.GREEN,f"CHANGE PIN DONE BY '{protocol}'")
            response, status  = makeCredProtocol2(new_pin,clientDataHash, RP_domain,user)
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
            util.printcolor(util.GREEN,f"MAKE CRED DONE BY '{protocol}'")
            response, status = getAsserationProtocol2(new_pin, clientDataHash, RP_domain, response)
            util.printcolor(util.GREEN,f"GET ASSERTION DONE BY '{protocol}'")
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
 
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "getPinRetries":
        scenarioCount += 1
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
            response , status = getPINRetriesProtocol1()
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
        elif protocol == "PROTOCOL_TWO":
            response , status = getPINRetriesProtocol2()
            if status == "00":
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : '{status}'")
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "notSet-ChangeFail-Set-Change-RetryCount":
        scenarioCount += 1
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin,new_pin)
            if status == "35":
                util.printcolor(util.GREEN, "CHANGE PIN DONE")
                response , status = setpinProtocol1(new_pin)
                if status == "00":
                    util.printcolor(util.GREEN, "SET PIN DONE")
                    old_pin = new_pin
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN, "CHANGE PIN DONE")
                        response , status = getPINRetriesProtocol1()
                        if status == "00":
                            util.printcolor(util.GREEN, "GET PIN RETRIES DONE")
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                    exit(0)
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)


        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin,new_pin)
            if status == "35":
                util.printcolor(util.GREEN, "CHANGE PIN DONE")
                response , status = setpinProtocol2(new_pin)
                if status == "00":
                    util.printcolor(util.GREEN, "SET PIN DONE")
                    old_pin = new_pin
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN, "CHANGE PIN DONE")
                        response , status = getPINRetriesProtocol2()
                        if status == "00":
                            util.printcolor(util.GREEN, "GET PIN RETRIES DONE")
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                    exit(0)
            else:
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : '{status}'")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "set-Change-Change-Verify":
        scenarioCount += 1
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin, new_pin)
            if status == "00":
                old_pin = new_pin
                response , status = changePINProtocol1(old_pin, new_pin)
                if status == "00":
                    response, status  = makeCredProtocol1(new_pin,clientDataHash, RP_domain,user)
                    util.printcolor(util.GREEN,f"MAKE CRED DONE BY '{protocol}'")
                    response, status = getAsserationProtocol1(new_pin, clientDataHash, RP_domain, response)
                    util.printcolor(util.GREEN,f"GET ASSERTION DONE BY '{protocol}'")

            if status != "00":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)

               
        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin, new_pin)
            if status == "00":
                old_pin = new_pin
                response , status = changePINProtocol2(old_pin, new_pin)
                if status == "00":
                    response, status  = makeCredProtocol2(new_pin,clientDataHash, RP_domain,user)
                    util.printcolor(util.GREEN,f"MAKE CRED DONE BY '{protocol}'")
                    response, status = getAsserationProtocol2(new_pin, clientDataHash, RP_domain, response)
                    util.printcolor(util.GREEN,f"GET ASSERTION DONE BY '{protocol}'")

            if status != "00":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "randomCurrentPin":
        scenarioCount += 1
        old_pin = "978675645342312011"
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
            response , status = changePINProtocol1(old_pin, new_pin)
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        elif protocol == "PROTOCOL_TWO":
            response , status = changePINProtocol2(old_pin, new_pin)
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        else:
            util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
            exit(0)
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "randomCurrentPin":
        scenarioCount += 1
        old_pin = "978675645342312011"
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "35":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    elif mode == "newPinShorterThanMinPin":
        scenarioCount += 1
        new_pin = "1234"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "37":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "newPinLongerThanMaxPin":
        scenarioCount += 1
        new_pin = "2" * 65
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "02":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "curPinShorterThanMinPin":
        scenarioCount += 1
        old_pin = "123"
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "31":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "curPinLongerThanMaxPin":
        scenarioCount += 1
        old_pin = "2" * 64
        new_pin = "1234567"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "31":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "curPinNewPinShorterThanMinPin":
        scenarioCount += 1
        old_pin = "123"
        new_pin = "123"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "31":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "curPinNewPinLongerThanMaxPin":
        scenarioCount += 1
        old_pin = "4" * 65
        new_pin = "5" * 65
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "02":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "newPinShorterThanMinPin_PinNotSet":
        scenarioCount += 1
        old_pin = "12345678"
        new_pin = "123"
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "35":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1


    elif mode == "newPinLongerThanMaxPin_PinNotSet":
        scenarioCount += 1
        old_pin = "12345678"
        new_pin = "8" * 64
        if protocol == "PROTOCOL_ONE":
           response , status = changePINProtocol1(old_pin, new_pin)
        elif protocol == "PROTOCOL_TWO":
           response , status = changePINProtocol2(old_pin, new_pin)
        else:
           util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
           exit(0)
        
        if status != "35":
            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
            exit(0)
        else:
            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
        DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
        passCount += 1

    elif mode == "curPinShorterThanMinPin_PinNotSet":
            scenarioCount += 1
            old_pin = "123"
            new_pin = "1235678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "curPinLongerThanMaxPin_PinNotSet":
            scenarioCount += 1
            old_pin = "7" * 68
            new_pin = "1235678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "curPinNewPinShorterThanMinPin_PinNotSet":
            scenarioCount += 1
            old_pin = "12"
            new_pin = "123"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "curPinNewPinLongerThanMaxPin_PinNotSet":
            scenarioCount += 1
            old_pin = "8" * 67
            new_pin = "7" * 64

            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "35":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "newPinWithoutPadding":
            scenarioCount += 1
            new_pin = "12"*8
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_newPINWithoutPadding(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2_newPINWithoutPadding(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "02":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "curPinNewPinLongerThanMaxPin_PinNotSet":
            scenarioCount += 1
            old_pin = "8" * 67
            new_pin = "7" * 70
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "37":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "reducePINRetriesCount":
            scenarioCount += 1
            old_pin = "8" * 8
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
                if status != "31":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
                    getPINRetriesProtocol1()
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
                if status != "31":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")
                    getPINRetriesProtocol2()
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "curPinNewPinLongerThanMaxPin_PinNotSet":
            scenarioCount += 1
            old_pin = "8" * 67
            new_pin = "7" * 70
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2(old_pin, new_pin)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "37":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}")   
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "multipleChangePinBlock":
            scenarioCount += 1
            old_pin = "8" * 8
            new_pin = "12345678"
            status = ""
            if protocol == "PROTOCOL_ONE":
                for i in range(3):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if i != 2:
                        if status == "31":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                    else:
                        if status == "34":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                for j in range(8):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{j+1} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{j+1} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol1()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol1()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                for a in range(3):
                    response , status = changePINProtocol1(old_pin, new_pin)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                for x in range(8):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{x+1} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{x+1} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol1()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol1()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                response , status = changePINProtocol1(old_pin, new_pin)
                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                if value == 1:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
                response , status = changePINProtocol1(old_pin, new_pin)
                if status == "32":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_BLOCKED") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                for i in range(3):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if i != 2:
                        if status == "31":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                    else:
                        if status == "34":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                for j in range(8):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{j+1} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{j+1} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol2()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol2()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                for a in range(3):
                    response , status = changePINProtocol2(old_pin, new_pin)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                for x in range(8):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{x+1} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{x+1} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol2()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol2()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                response , status = changePINProtocol2(old_pin, new_pin)
                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                if value == 1:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
                response , status = changePINProtocol2(old_pin, new_pin)
                if status == "32":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_BLOCKED") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)  
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1
    
    
    elif mode == "multipleIncorrectChangePin_LastCorrectChangePIN":
            scenarioCount += 1
            old_pin = "8" * 8
            new_pin = "12345678"
            status = ""
            if protocol == "PROTOCOL_ONE":
                for i in range(3):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if i != 2:
                        if status == "31":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                    else:
                        if status == "34":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                for j in range(8):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{j} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{j} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol1()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol1()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                for a in range(3):
                    response , status = changePINProtocol1(old_pin, new_pin)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                for x in range(8):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{x} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{x} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol1()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol1()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                response , status = changePINProtocol1(old_pin, new_pin)
                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                if value == 1:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
                response , status = changePINProtocol1(curpin, new_pin)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_OK") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                if value >= 8:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
            elif protocol == "PROTOCOL_TWO":
                for i in range(3):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if i != 2:
                        if status == "31":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                    else:
                        if status == "34":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                            exit(0)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                for j in range(8):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{j} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{j} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol2()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol2()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                for a in range(3):
                    response , status = changePINProtocol2(old_pin, new_pin)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                for x in range(8):
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "34":
                        util.printcolor(util.GREEN,f"{x} Time EXPECTED STATUS CODE : {status}") 
                    else:
                        util.printcolor(util.RED,f"{x} Time UNEXPECTED STATUS CODE : {status}") 
                        exit(0)
                response, status = getPINRetriesProtocol2()
                value1 = getRetryCountInInteger(response)
                if value == value1:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value1})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value1})") 
                    exit(0)
                util.ResetCardPower()
                util.ConnectJavaCard()
                util.APDUhex("00a4040008a0000006472f0001", "Select applet")
                response, status = getPINRetriesProtocol2()
                value2 = getRetryCountInInteger(response)
                if value == value2:
                    util.printcolor(util.GREEN,f" PIN Retries Count is same as previous : Previous({value}), Current({value2})") 
                else:
                    util.printcolor(util.RED,f" PIN Retries Count is NOT same as previous : Previous({value}), Current({value2})") 
                    exit(0)
                response , status = changePINProtocol2(old_pin, new_pin)
                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                if value == 1:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
                response , status = changePINProtocol2(curpin, new_pin)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_OK") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}") 
                    exit(0)
                response, status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                if value >= 8:
                    util.printcolor(util.GREEN,f"Current PIN Retries Count is {value}") 
                else:
                    util.printcolor(util.RED,f"Current PIN Retries Count is {value}") 
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)     
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1        
    
    
    elif mode == "unsupportedProtocolChangePin":
            scenarioCount += 1
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "02":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_INVALID_PARAMETER") 
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "invalidSubCommandChangePin":
            scenarioCount += 1
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "3E":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_INVALID_SUBCOMMAND") 
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1
    
    elif mode == "missingMandatoryParameters":
            scenarioCount += 1
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":

                # Case 1: Missing pinUvAuthProtocol
                case = "MissingpinUvAuthProtocol"
                util.printcolor(util.YELLOW, "Case 1: Missing pinUvAuthProtocol")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 1 => Missing pinUvAuthProtocol : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 1 => Missing pinUvAuthProtocol : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 2: Missing subCommand
                case = "MissingsubCommand"
                util.printcolor(util.YELLOW, "Case 2: Missing subCommand")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 2 => Missing subCommand : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 2 => Missing subCommand : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 3: Missing keyAgreement
                case = "MissingkeyAgreement"
                util.printcolor(util.YELLOW, "Case 3: Missing keyAgreement")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 3 => Missing keyAgreement : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 3 => Missing keyAgreement : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 4: Missing pinHashEnc
                case = "MissingpinHashEnc"
                util.printcolor(util.YELLOW, "Case 4: Missing pinHashEnc")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 4 => Missing pinHashEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 4 => Missing pinHashEnc : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 5: Missing newPinEnc
                case = "MissingnewPinEnc"
                util.printcolor(util.YELLOW, "Case 5: Missing newPinEnc")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 5 => Missing newPinEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 5 => Missing newPinEnc : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 6: Missing pinUvAuthParam
                case = "MissingpinUvAuthParam"
                util.printcolor(util.YELLOW, "Case 6: Missing pinUvAuthParam")
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 6 => Missing pinUvAuthParam : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 6 => Missing pinUvAuthParam : {status} - CTAP2_ERR_MISSING_PARAMETER") 

            elif protocol == "PROTOCOL_TWO":
                # Case 1: Missing pinUvAuthProtocol
                case = "MissingpinUvAuthProtocol"
                util.printcolor(util.YELLOW, "Case 1: Missing pinUvAuthProtocol")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 1 => Missing pinUvAuthProtocol : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 1 => Missing pinUvAuthProtocol : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 2: Missing subCommand
                case = "MissingsubCommand"
                util.printcolor(util.YELLOW, "Case 2: Missing subCommand")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 2 => Missing subCommand : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 2 => Missing subCommand : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 3: Missing keyAgreement
                case = "MissingkeyAgreement"
                util.printcolor(util.YELLOW, "Case 3: Missing keyAgreement")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 3 => Missing keyAgreement : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 3 => Missing keyAgreement : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 4: Missing pinHashEnc
                case = "MissingpinHashEnc"
                util.printcolor(util.YELLOW, "Case 4: Missing pinHashEnc")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 4 => Missing pinHashEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 4 => Missing pinHashEnc : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 5: Missing newPinEnc
                case = "MissingnewPinEnc"
                util.printcolor(util.YELLOW, "Case 5: Missing newPinEnc")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 5 => Missing newPinEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 5 => Missing newPinEnc : {status} - CTAP2_ERR_MISSING_PARAMETER") 

                # Case 6: Missing pinUvAuthParam
                case = "MissingpinUvAuthParam"
                util.printcolor(util.YELLOW, "Case 6: Missing pinUvAuthParam")
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "14":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 6 => Missing pinUvAuthParam : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 6 => Missing pinUvAuthParam : {status} - CTAP2_ERR_MISSING_PARAMETER") 
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "invalidKeyAgreement":
            scenarioCount += 1
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
            elif protocol == "PROTOCOL_TWO":
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            
            if status != "02":
                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                exit(0)
            else:
                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_INVALID_PARAMETER") 
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    # elif mode == "invalidKeyAgreement":
    #         new_pin = "12345678"
    #         if protocol == "PROTOCOL_ONE":
    #             response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
    #         elif protocol == "PROTOCOL_TWO":
    #             response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
    #         else:
    #             util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
    #             exit(0)
            
    #         if status != "02":
    #             util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
    #         else:
    #             util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_INVALID_PARAMETER") 
    

    elif mode == "invalidParametersForChangePIN":
            scenarioCount += 1
            new_pin = "12121212"
            if protocol == "PROTOCOL_ONE":
                # Case 1: Invalid pinUvAuthProtocol
                util.printcolor(util.YELLOW, "Case 1: Invalid pinUvAuthProtocol")
                case = "invalidProtocolChangePin"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 1 => Invalid pinUvAuthProtocol : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 1 => Invalid pinUvAuthProtocol : {status} - CTAP1_ERR_INVALID_PARAMETER") 

                # Case 2: Invalid subCommand
                util.printcolor(util.YELLOW, "Case 2: Invalid subCommand")
                case = "invalidSubCommandChangePin1"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "3E":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 2 => Invalid subCommand : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 2 => Invalid subCommand : {status} - CTAP2_ERR_INVALID_SUBCOMMAND") 

                # Case 3: Invalid keyAgreement
                util.printcolor(util.YELLOW, "Case 3: Invalid keyAgreement")
                case = "invalidKeyAgreementChangePin"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 3 => Invalid keyAgreement : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 3 => Invalid keyAgreement : {status} - CTAP1_ERR_INVALID_PARAMETER") 
    
                # Case 4: Invalid pinHashEnc
                util.printcolor(util.YELLOW, "Case 4: Invalid pinHashEnc")
                case = "invalidPinHashEncChangePin"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "31":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 4 => Invalid pinHashEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 4 => Invalid pinHashEnc : {status} - CTAP2_ERR_PIN_INVALID") 
    
                # Case 5: Invalid newPinEnc
                util.printcolor(util.YELLOW, "Case 5: Invalid newPinEnc")
                case = "invalidNewPinEncChangePin"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 5 => Invalid newPinEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 5 => Invalid newPinEnc : {status} - CTAP1_ERR_INVALID_PARAMETER") 
    
                # Case 6: Invalid pinUvAuthParam
                util.printcolor(util.YELLOW, "Case 6: Invalid pinUvAuthParam")
                case = "invalidPinUvAuthParamChangePin"
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)
                if status != "33":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 6 => Invalid pinUvAuthParam : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 6 => Invalid pinUvAuthParam : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
    

            elif protocol == "PROTOCOL_TWO":
                # Case 1: Invalid pinUvAuthProtocol
                util.printcolor(util.YELLOW, "Case 1: Invalid pinUvAuthProtocol")
                case = "invalidProtocolChangePin"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 1 => Invalid pinUvAuthProtocol : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 1 => Invalid pinUvAuthProtocol : {status} - CTAP1_ERR_INVALID_PARAMETER") 

                # Case 2: Invalid subCommand
                util.printcolor(util.YELLOW, "Case 2: Invalid subCommand")
                case = "invalidSubCommandChangePin1"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "3E":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 2 => Invalid subCommand : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 2 => Invalid subCommand : {status} - CTAP2_ERR_INVALID_SUBCOMMAND") 

                # Case 3: Invalid keyAgreement
                util.printcolor(util.YELLOW, "Case 3: Invalid keyAgreement")
                case = "invalidKeyAgreementChangePin"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 3 => Invalid keyAgreement : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 3 => Invalid keyAgreement : {status} - CTAP1_ERR_INVALID_PARAMETER") 
    
                # Case 4: Invalid pinHashEnc
                util.printcolor(util.YELLOW, "Case 4: Invalid pinHashEnc")
                case = "invalidPinHashEncChangePin"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "31":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 4 => Invalid pinHashEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 4 => Invalid pinHashEnc : {status} - CTAP2_ERR_PIN_INVALID") 
    
                # Case 5: Invalid newPinEnc
                util.printcolor(util.YELLOW, "Case 5: Invalid newPinEnc")
                case = "invalidNewPinEncChangePin"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "02":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 5 => Invalid newPinEnc : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 5 => Invalid newPinEnc : {status} - CTAP1_ERR_INVALID_PARAMETER") 
    
                # Case 6: Invalid pinUvAuthParam
                util.printcolor(util.YELLOW, "Case 6: Invalid pinUvAuthParam")
                case = "invalidPinUvAuthParamChangePin"
                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)
                if status != "33":
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE for Case 6 => Invalid pinUvAuthParam : {status}")
                    exit(0)
                else:
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE for Case 6 => Invalid pinUvAuthParam : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
    
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1
    
    elif mode == "incorrectPINHashEnc":
            scenarioCount += 1
            new_pin = "12345698"
            if protocol == "PROTOCOL_ONE":
                case = "invalidPinHashEncChangePin1"
                response , status = getPINRetriesProtocol1()
                value = getRetryCountInInteger(response)
                util.printcolor(util.BLUE,f"RETRY COUNTS BEFORE CHANGE PIN : {value}") 

                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)

                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_INVALID") 
                    response , status = getPINRetriesProtocol1()
                    value1 = getRetryCountInInteger(response)
                    util.printcolor(util.BLUE,f"RETRY COUNTS AFTER CHANGE PIN : {value1}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
               
                case = "invalidPinHashEncChangePin2"
                response , status = getPINRetriesProtocol2()
                value = getRetryCountInInteger(response)
                util.printcolor(util.BLUE,f"RETRY COUNTS BEFORE CHANGE PIN : {value}") 

                response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)

                if status == "31":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_INVALID") 
                    response , status = getPINRetriesProtocol2()
                    value1 = getRetryCountInInteger(response)
                    util.printcolor(util.BLUE,f"RETRY COUNTS AFTER CHANGE PIN : {value1}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "incorrectPinHashEnc3Times":
            scenarioCount += 1
            new_pin = "12345678"
            if protocol == "PROTOCOL_ONE":
                case = "invalidPinHashEncChangePin"
                for i in range(3):
                    response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, case)

                if status == "34":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE AFTER GIVING 3 CONSECUTIVE INCORRECT PIN HASH ENC : {status} - CTAP2_ERR_PIN_AUTH_BLOCKED") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE AFTER GIVING 3 CONSECUTIVE INCORRECT PIN HASH ENC : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                case = "invalidPinHashEncChangePin"
                for j in range(3):
                    response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, case)

                if status == "34":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE AFTER GIVING 3 CONSECUTIVE INCORRECT PIN HASH ENC : {status} - CTAP2_ERR_PIN_AUTH_BLOCKED") 
                else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE AFTER GIVING 3 CONSECUTIVE INCORRECT PIN HASH ENC : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "malformedNewPINEnc":
            scenarioCount += 1
            new_pin = "11223344"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
                if status == "33":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
                    if status == "33":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "newPinEncNotPaddedto64Bytes":
            scenarioCount += 1
            new_pin = "11223344"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
                if status == "02":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_INVALID_PARAMETER") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
                    if status == "02":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_INVALID_PARAMETER") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "forceChangePINisTRUE":
            scenarioCount += 1
            new_pin = "12345687"
            if protocol == "PROTOCOL_ONE":
                permission = 0x20  # authenticator config
                token = getPINTokenWithPermissionProtocol1(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = True
                reponse, status = newMinPinLength_forcechangePin_Protocol1(token, subCommand, forceChangePIN)
                if status == "00":
                    response , status = changePINProtocol1(old_pin, old_pin)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                    # util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND: {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                permission = 0x20  # authenticator config
                token, pubkey = getPINTokenWithPermissionProtocol2(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = True
                reponse, status = newMinPinLength_forcechangePin_Protocol2(token, subCommand, forceChangePIN)
                if status == "00":
                    response , status = changePINProtocol2(old_pin, old_pin)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                    else:
                        util.APDUhex("80100000010400", "GetInfo")
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                    # util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND: {status}") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "forceChangePINisTRUEWithDifferentPIN":
            scenarioCount += 1
            new_pin = "123456"
            if protocol == "PROTOCOL_ONE":
                permission = 0x20  # authenticator config
                token = getPINTokenWithPermissionProtocol1(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = True
                reponse, status = newMinPinLength_forcechangePin_Protocol1(token, subCommand, forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND: {status}") 

                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_OK") 
                        util.printcolor(util.YELLOW,f"Checking forcePINChange Set to 'FALSE', by doing same PIN Change...") 
                        response , status = changePINProtocol1(new_pin, new_pin)
                        if status == "00":
                             util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND, Now forcePINChange is set to 'False' : {status} - CTAP2_OK") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND, forcePINChange is may be still set to 'True'   : {status}")
                            exit(0)

                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                permission = 0x20  # authenticator config
                token, pubkey = getPINTokenWithPermissionProtocol2(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = True
                reponse, status = newMinPinLength_forcechangePin_Protocol2(token, subCommand, forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND: {status}") 

                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_OK") 

                        util.printcolor(util.YELLOW,f"Checking forcePINChange Set to 'FALSE', by doing same PIN Change...") 
                        response , status = changePINProtocol2(new_pin, new_pin)
                        if status == "00":
                             util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND, Now forcePINChange is set to 'False' : {status} - CTAP2_OK") 
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND, forcePINChange is may be still set to 'True'   : {status}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "invalidatePinUvAuthToken":
            scenarioCount += 1
            new_pin = "11223344"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_invalidatePinAuth(old_pin, new_pin)
                if status == "33":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2_invalidatePinAuth(old_pin, new_pin)
                    if status == "33":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "invalidatePinUvAuthTokenWithSamePIN":
            scenarioCount += 1
            new_pin = "11223344"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_invalidatePinAuth(old_pin, old_pin)
                if status == "33":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2_invalidatePinAuth(old_pin, old_pin)
                    if status == "33":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1


    elif mode == "forceMinimumNewPinLengthChangePIN":
            scenarioCount += 1
            minLength = 10
            new_pin = "13456872"
            if protocol == "PROTOCOL_ONE":
                permission = 0x20  # authenticator config
                token = getPINTokenWithPermissionProtocol1(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = False
                reponse, status = newMinPinLength_forcechangePin_withMinLength_Protocol1(token, subCommand, minLength,forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR MINIMUM PIN LENGTH(AUTHENTICATOR CONFIG) COMMAND: {status}") 

                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                permission = 0x20  # authenticator config
                token, pubkey = getPINTokenWithPermissionProtocol2(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = False
                reponse, status = newMinPinLength_forcechangePin_withMinLength_Protocol2(token, subCommand, minLength, forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR MINIMUM PIN LENGTH(AUTHENTICATOR CONFIG) COMMAND: {status}") 

                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "forceMinimumNewPinLengthChangePIN_ValidCase":
            scenarioCount += 1
            minLength = 10
            new_pin = "1345687201"
            if protocol == "PROTOCOL_ONE":
                permission = 0x20  # authenticator config
                token = getPINTokenWithPermissionProtocol1(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = False
                reponse, status = newMinPinLength_forcechangePin_withMinLength_Protocol1(token, subCommand, minLength,forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR MINIMUM PIN LENGTH(AUTHENTICATOR CONFIG) COMMAND: {status}") 

                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_OK") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                permission = 0x20  # authenticator config
                token, pubkey = getPINTokenWithPermissionProtocol2(old_pin, permission)
                subCommand = 0x03
                forceChangePIN = False
                reponse, status = newMinPinLength_forcechangePin_withMinLength_Protocol2(token, subCommand, minLength, forceChangePIN)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR MINIMUM PIN LENGTH(AUTHENTICATOR CONFIG) COMMAND: {status}") 

                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status} - CTAP2_OK") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR CHANGE PIN COMMAND : {status}")
                        exit(0)
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE FOR FORCE CHANGE PIN COMMAND : {status}")
                    exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    elif mode == "newAlphanumericPIN":
            scenarioCount += 1
            new_pin = "@3#$%^&*()!><:"''"124\|/?.,<123abcs"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1(old_pin, new_pin)
                if status == "00":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_OK") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2(old_pin, new_pin)
                    if status == "00":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_OK") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "nonZeroPadding":
            scenarioCount += 1
            new_pin = "12345687"
            if protocol == "PROTOCOL_ONE":
                response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin,mode)
                if status == "37":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    
    elif mode == "protocolMismatch":
            scenarioCount += 1
            new_pin = "1234567891"
            if protocol == "PROTOCOL_ONE":
                # response , status = changePINProtocol1_InvalidParameters(old_pin, new_pin, mode)
                response , status = change_client_pin_swapping_protocol2(old_pin, new_pin)
                if status == "33":
                    util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                else:
                    util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                    exit(0)

            elif protocol == "PROTOCOL_TWO":
                    # response , status = changePINProtocol2_InvalidParameters(old_pin, new_pin, mode)
                    response , status = change_client_pin_swapping_protocol1(old_pin, new_pin)
                    if status == "33":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_AUTH_INVALID") 
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1

    elif mode == "checkRetryCountsForDifferentStatusCode":
            scenarioCount += 1
            new_pin = "1234"
            fixCount = 0
            dynCount = 1
            if protocol == "PROTOCOL_ONE":
                for i in range(8):
                    response , status = changePINProtocol1(old_pin, new_pin)
                    if status == "37":
                        util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                        response, status = getPINRetriesProtocol1()
                        if status == "00":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_SUCCESS") 
                            dynCount = getRetryCountInInteger(response)
                            if i == 0:
                                fixCount = dynCount
                            if fixCount == dynCount:
                                util.printcolor(util.GREEN,f"Current PIN Retry Count {dynCount} is same as Previous {fixCount}") 
                            else:
                                util.printcolor(util.RED,f"Current PIN Retry Count {dynCount} is NOT same as Previous {fixCount}") 
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                            exit(0)
                    else:
                        util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                        exit(0)

                

            elif protocol == "PROTOCOL_TWO":
                    for i in range(8):
                        response , status = changePINProtocol2(old_pin, new_pin)
                        if status == "37":
                            util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP2_ERR_PIN_POLICY_VIOLATION") 
                            response, status = getPINRetriesProtocol2()
                            if status == "00":
                                util.printcolor(util.GREEN,f"EXPECTED STATUS CODE : {status} - CTAP1_ERR_SUCCESS") 
                                dynCount = getRetryCountInInteger(response)
                                if i == 0:
                                    fixCount = dynCount
                                if fixCount == dynCount:
                                    util.printcolor(util.GREEN,f"Current PIN Retry Count {dynCount} is same as Previous {fixCount}") 
                                else:
                                    util.printcolor(util.RED,f"Current PIN Retry Count {dynCount} is NOT same as Previous {fixCount}") 
                                    exit(0)
                            else:
                                util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                                exit(0)
                        else:
                            util.printcolor(util.RED,f"UNEXPECTED STATUS CODE : {status}")
                            exit(0)
            else:
                util.printcolor(util.RED,f"Error: Caught Invalid/Unsupported Protocol : '{protocol}'")
                exit(0)
            DocumentCreation.add_detailed_row(DETAILED_TABLE, COMMAND_NAME, PROTOCOL, SCENARIO, PASS)
            passCount += 1



    # elif mode == "pinlengthLess":
    #     new_pin = "12"                               # shorter than minimum → invalid

    # elif mode == "pinlengthexced":
    #     new_pin = "A" * 70                           # longer than maximum → invalid

    # elif mode == "getPinRetries":
    #     new_pin = "123456"                             # Get pin retries of valid PIN

    # elif mode == "multipleChangePinOperation":
    #     new_pin = "123456"                             # Change Pin operation multiple times

    # elif mode == "randomCurrentPin":
    #     new_pin = "123456"           
    #     old_pin = "A6B5C4"                             # Change PIN operation with random current pin without pin Set

    # elif mode == "newPinShorterThanMinPin":
    #     new_pin = "123"                                # Change PIN operation with new PIN shorter than minimum PIN Length

    # elif mode == "newPinLongerThanMaxPin":
    #     new_pin = "1" * 70                             # Change PIN operation with new PIN longer than maximum PIN Length

    # elif mode == "curPinShorterThanMinPin":
    #     new_pin = "123456"                             # Change PIN operation with current PIN shorter than minimum PIN Length
    #     old_pin = "123"

    # elif mode == "curPinLongerThanMaxPin":
    #     new_pin = "123456"                              # Change PIN operation with current PIN longer than maximum PIN Length
    #     old_pin = "A" * 70

    # elif mode == "curPinNewPinShorterThanMinPin":
    #     new_pin = "123"                                 # Change PIN operation with current PIN and new PIN both shorter than minimum PIN Length
    #     old_pin = "123"

    # elif mode == "curPinNewPinLongerThanMaxPin":
    #     new_pin = "A" * 70                              # Change PIN operation with current PIN and new PIN both longer than maximum PIN Length
    #     old_pin = "A" * 70

    # elif mode == "newPinShorterThanMinPin_PinNotSet":
    #     new_pin = "123"                                # Change PIN operation with new PIN shorter than minimum PIN Length when pin not set

    # elif mode == "newPinLongerThanMaxPin_PinNotSet":
    #     new_pin = "A" * 70                             # Change PIN operation with new PIN longer than maximum PIN Length when pin not set

    # elif mode == "curPinShorterThanMinPin_PinNotSet":
    #     new_pin = "123456"                             # Change PIN operation with current PIN shorter than minimum PIN Length when pin not set
    #     old_pin = "123"

    # elif mode == "curPinLongerThanMaxPin_PinNotSet":
    #     new_pin = "123456"                              # Change PIN operation with current PIN longer than maximum PIN Length when pin not set
    #     old_pin = "A" * 70

    # elif mode == "curPinNewPinShorterThanMinPin_PinNotSet":
    #     new_pin = "123"                                 # Change PIN operation with current PIN and new PIN both shorter than minimum PIN Length when pin not set
    #     old_pin = "123"

    # elif mode == "curPinNewPinLongerThanMaxPin_PinNotSet":
    #     new_pin = "A" * 70                              # Change PIN operation with current PIN and new PIN both longer than maximum PIN Length when pin not set
    #     old_pin = "A" * 70

    # elif mode == "newPinWithoutPadding":
    #     new_pin = "12345678"                            # Change PIN Operation when new pin is not padded

    # # Decrementing retry counts using changepin command by giving incorrect pin
    # elif mode == "changePinBlock":
    #     old_pin = "554432"
    #     new_pin = "768987"
    #     response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
    #     fixRetryCount = getRetryCountInInteger(response)
    #     util.printcolor(util.YELLOW, f"Total Allowed Retry Counts : {fixRetryCount}")
    #     retryCount = fixRetryCount

    #     if fixRetryCount >= 1:
    #          while retryCount > 1:
    #             retryCount = wrongPinChangeAndPowerCycle(old_pin, new_pin)
    #             if retryCount == 1:    
    #                 util.printcolor(util.REDWHITE, f"Remaining Allowed Retry Counts : {retryCount}... Now Performing Chnage PIN to block")
    #                 old_pin = "554432"
    #                 new_pin = "768987"

    #             elif retryCount == 0:
    #                 util.printcolor(util.RED, f"PIN is blocked already !")    

    #             else:
    #                util.printcolor(util.YELLOW, f"Remaining Allowed Retry Counts : {retryCount}")
    #     else:
    #         util.printcolor(util.RED, f"PIN is blocked already !")

    # elif mode == "block-Set-Change-Verify":
    #     new_pin = "12345678"
    #     old_pin = "12345678"
    #     changePINOnly(old_pin, new_pin)
    #     util.APDUhex("80100000010700", "Reset Card", checkflag=True)  #Reset Card
    #     util.APDUhex("80100000010400", "GetInfo")
    #     Setpinp22.setpin(old_pin)  #Set new pin 12345678
    
    # elif mode == "unsupportedProtocolChangePin":
    #     new_pin = "12345678"

    # elif mode == "invalidSubCommandChangePin":
    #     new_pin = "12345678"

    # elif mode == "missing_newPinEnc_parameter":
    #     new_pin = "12345678"

    # elif mode == "invalidKeyAgreement":
    #     new_pin = "12345678"

    # elif mode == "invalidHMAC":
    #     new_pin = "12345678"

    # elif mode == "incorrectPinHashEnc":
    #     new_pin = "12345678"
    #     response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
    #     fixRetryCount = getRetryCountInInteger(response)
    #     if fixRetryCount > 1:
    #         util.printcolor(util.YELLOW, f"Total Allowed Retry Counts : {fixRetryCount}")
    #     else:
    #         util.printcolor(util.RED, f"Test Case aborted in middle remaining Retry Counts is not >= 1, retryCount => {fixRetryCount}")
    #         return 0
        
    # elif mode == "incorrectPinHashEnc3Times":
    #     new_pin = "12345678"

    # elif mode == "incorrectNewPinEnc":
    #     new_pin = "12345678"

    # elif mode == "newPinEncNotPaddedto64Bytes":
    #     new_pin = "12345678"

    # elif mode == "forceChangePINisTRUE":
    #     new_pin = "12345678"

        # util.APDUhex("80100000010400", "Get Info")
        # permission = 0x20  # authenticator config
        # pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
        # subCommand = 0x03
        # apdu=authenticatorConfig.newMinPinLength_forcechangePin(pinToken,subCommand)
        # response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
    #     util.APDUhex("80100000010400", "Get Info")

    # elif mode == "forceChangePINisTRUE_2":
    #     new_pin = "12345678"
    #     util.APDUhex("80100000010400", "Get Info")
    #     permission = 0x20  # authenticator config
    #     pinToken, pubkey =credentialManagement.getPINtokenPubkey(pin, permission)
    #     subCommand = 0x03
    #     apdu=authenticatorConfig.newMinPinLength_forcechangePin(pinToken,subCommand)
    #     response, status = util.APDUhex(apdu, "authenticatorConfig(0x0D) : setMinPINLength(0x03)", checkflag=True)
    #     util.APDUhex("80100000010400", "Get Info")
    #     changePINOnly(old_pin, new_pin)
    #     util.printcolor(util.RED, "First time change Pin with similar pins (old pin and new pin) must be fail")
    #     new_pin = "123456"
    #     changePINOnly(old_pin, new_pin)
    #     util.printcolor(util.YELLOW, "Second time change Pin with different pins (old pin and new pin) must be succeed")
    #     old_pin = "123456"
    #     changePINOnly(old_pin, new_pin)
    #     util.printcolor(util.YELLOW, "Third time change Pin with similar pins (old pin and new pin) must be succeed, hence forceChangePin is set to False again.")

    # elif mode == "invalidatePinUvAuthToken":
    #     new_pin = "123456"
    
    # util.printcolor(util.YELLOW, f" Selected new PIN for mode '{mode}': {new_pin}")
    # util.printcolor(util.YELLOW, f" Selected current PIN for mode '{mode}': {old_pin}")
    
    # util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    # util.APDUhex("80100000010400", "GetInfo")

    # #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    # cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    # cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    # decoded_data = cbor2.loads(cbor_bytes)

    # if mode == "invalidKeyAgreement":
    #     key_agreement, sharedSecret = util.wrongencapsulate(decoded_data[1])
    # else:
    #     key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    # if mode == "incorrectPinHashEnc":
    #     oldPinHash = util.sha256(old_pin.encode())[:8]
    # elif mode == "incorrectPinHashEnc3Times":
    #     oldPinHash = util.sha256(old_pin.encode())[:8]
    # else:
    #     oldPinHash = util.sha256(old_pin.encode())[:16]
    # pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    # if mode ==  "newPinWithoutPadding":
    #     newPinPadded = util.withoupadded(new_pin)
    # elif mode == "newPinEncNotPaddedto64Bytes":
    #     newPinPadded = util.pad_pin_not_64bytes(new_pin)
    #     util.printcolor(util.BLUE, f"New Padded PIN : {util.toHex(newPinPadded)}")
    # else:
    #     newPinPadded = util.pad_pin(new_pin)

    # newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    # #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    # if mode == "invalidHMAC":
    #     combined = newPinEnc + pinHashEnc + os.urandom(1)
    # else:
    #     combined = newPinEnc + pinHashEnc

    # hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    # pinAuth = hmac_value[:32]

    # if mode == "invalidatePinUvAuthToken":
    #     pinAuth2 = pinAuth

    # if mode == "unsupportedProtocolChangePin":
    #     apdu = createCBORchangePIN_protocol3(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    # elif mode == "missing_newPinEnc_parameter":
    #     apdu = createCBORchangePIN_protocol2_missing_newPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    # elif mode == "invalidSubCommandChangePin":
    #     apdu = createCBORchangePIN_protocol2_invalid_subcommand(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    # elif mode == "incorrectNewPinEnc":
    #  apdu = createCBORchangePIN_protocol2_incorrectNewPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement)

    # else:
    #     apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    
    # util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

    # if mode == "block-Set-Change-Verify":
    #     verifyChangePIN("block-Set-Change-Verify",old_pin, RP_domain, user)

    # if mode == "getPinRetries":
    #     util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)

    # if mode == "incorrectPinHashEnc":
    #     response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
    #     redRetryCount = getRetryCountInInteger(response)
    #     if redRetryCount == fixRetryCount-1:
    #          util.printcolor(util.YELLOW, f"Total Allowed Retry Counts reduced by 1, current retry counts remaining : {redRetryCount}")
    #     else:
    #         util.printcolor(util.RED, f"Total Allowed Retry Counts not reduced by 1, current retry counts remaining : {redRetryCount}")

    # if mode == "incorrectPinHashEnc3Times":
    #     for i in range(2):
    #         changePINIncorrectPinHash(old_pin, new_pin)

    # if mode == "invalidatePinUvAuthToken":
    #     old_pin = "123456"
    #     new_pin = "123456"
    #     changePINOnlyWithPinAuthToken(old_pin, new_pin, pinAuth2)

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
        cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

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


def getPINRetriesProtocol1():
        response, status = util.APDUhex("801000000606A20101020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")
        return response, status


def getPINRetriesProtocol2():
        response, status = util.APDUhex("801000000606A20102020100", "Client PIN subcmd 0x01 getPinRetries", checkflag=True)
        value = getRetryCountInInteger(response)
        print("*************** Current PIN Retry Count  : ",value," ***************")
        return response, status


def getRetryCountInInteger(response):
    # Convert to bytes
    data = bytes.fromhex(response)

    # Find index of key 0x03
    key = 0x03
    index = data.index(key)

    # Get value after key
    value_hex = data[index + 1]

    # Convert to int
    value_int = int(value_hex)
    return value_int



def createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu

def createCBORchangePIN_protocol2_InvalidParameters(pinHashEnc, newPINenc, pinAuth, keyAgreement, mode):
    # Step 5: Create CBOR command map
    if mode == "unsupportedProtocolChangePin" or mode == "invalidProtocolChangePin":
        protocol = 3
    else:
        protocol = 2

    if mode == "invalidSubCommandChangePin" or mode == "invalidSubCommandChangePin1":
        subCommand = 10
    else:
        subCommand = 4
    
    if mode == "MissingpinUvAuthProtocol":
        cbor_map = {
            # 1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingsubCommand":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            # 2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingkeyAgreement":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            # 3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingpinHashEnc":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            # 6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingnewPinEnc":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            # 5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingpinUvAuthParam":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            # 4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    else:
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu

def createCBORchangePIN_protocol2_incorrectNewPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: pinHashEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def createCBORchangePIN_protocol2_missing_newPinEnc(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        # 5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def createCBORchangePIN_protocol2_invalid_keyAgreement(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def createCBORchangePIN_protocol2_invalid_subcommand(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 33,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def createCBORchangePIN_protocol2_invalid_hmac(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 2,               # pinProtocol = 2
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80108000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def createCBORchangePIN_protocol3(pinHashEnc, newPinEnc, pinAuth, key_agreement):
    # Step 5: Create CBOR command map
    cbor_map = {
        1: 3,               # pinProtocol = 3
        2: 4,               # subCommand = Change PIN
        3: key_agreement,   # keyAgreement (COSE key)
        4: pinAuth,         # pinAuth
        5: newPinEnc,       # newPinEnc
        6: pinHashEnc       # pinHashEnc (oldPin hashed)
    }
    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
    return apdu

def verifyChangePIN(mode, curpin, rp, user):
    util.printcolor(util.YELLOW, "")
    # ------------------------------
    #   TEST DESCRIPTIONS
    # ------------------------------

    descriptions = {
        "pinVerify": """Test started: P-5:
Initiate a protected operation—such as credential management—to verify the newly updated PIN. Ensure all parameters in the verification command are correct. The authenticator should respond with CTAP2_OK.""",

}

    if mode == "pinVerify":
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
    pinToken, pubkey = getPINtokenPubkeyTemp(curpin)
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

    makeCredAPDU = build_make_cred_apdu(
        clientDataHash,
        rp_entity,
        user_entity,
        pubKeyCredParams,
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
                         pubKeyCredParams,  pubkey, pinAuthToken):

    options = {"rk": True}

    cbor_hash    = cbor2.dumps(clientDataHash).hex().upper()
    cbor_rp      = cbor2.dumps(rp_entity).hex().upper()
    cbor_user    = cbor2.dumps(user_entity).hex().upper()
    cbor_params  = cbor2.dumps(pubKeyCredParams).hex().upper()
    cbor_options = cbor2.dumps(options).hex().upper()
    cbor_pinAuth = cbor2.dumps(pinAuthToken).hex().upper()

    # CBOR MAP (A8 = 8 entries)
    dataCBOR  = "A7"
    dataCBOR += "01" + cbor_hash
    dataCBOR += "02" + cbor_rp
    dataCBOR += "03" + cbor_user
    dataCBOR += "04" + cbor_params
    dataCBOR += "07" + cbor_options
    dataCBOR += "08" + cbor_pinAuth
    dataCBOR += "09" + "02"

    finalPayload = "01" + dataCBOR
    payload = bytes.fromhex(finalPayload)

    # Single APDU
    if len(payload) <= 255:
        lc = f"{len(payload):02X}"
        return "80100000" + lc + finalPayload

    # Chained APDU
    return util.build_chained_apdus(payload)

def getPINtokenPubkeyTemp(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
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

def getPINtokenPubkey(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
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

def getPINtokenPubkeyProtocol2(curpin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU = createGetPINtokenProtocol2(pinHashEnc,key_agreement)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True)

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

def changePINOnly(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

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
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu

def createCBORchangePIN_protocol1_InvalidParameters(pinHashEnc, newPINenc, pinAuth, keyAgreement,mode):
    """
    Constructs a CBOR-encoded APDU command for ClientPIN ChangePIN (subCommand = 0x04)
    """

    if mode == "unsupportedProtocolChangePin" or mode == "invalidProtocolChangePin":
        protocol = 3
    else:
        protocol = 1

    if mode == "invalidSubCommandChangePin" or mode == "invalidSubCommandChangePin1":
        subCommand = 10
    else:
        subCommand = 4

    if mode == "MissingpinUvAuthProtocol":
        cbor_map = {
            # 1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingsubCommand":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            # 2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingkeyAgreement":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            # 3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingpinHashEnc":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            # 6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingnewPinEnc":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            # 5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    elif mode == "MissingpinUvAuthParam":
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            # 4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }
    else:
        cbor_map = {
            1: protocol,               # pinProtocol = 1
            2: subCommand,               # subCommand = 0x04 (change PIN)
            3: keyAgreement,    # keyAgreement (MAP)
            4: pinAuth,         # pinAuth (first 16 bytes of HMAC)
            5: newPINenc,       # newPinEnc (AES-256-CBC of new PIN padded)
            6: pinHashEnc       # pinHashEnc (AES-256-CBC of SHA-256(current PIN)[:16])
        }

    encoded = cbor2.dumps(cbor_map)
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper() + "00"
    return apdu


def changePINProtocol1_invalidatePinAuth(current_pin: str, new_pin: str):
    for i in range(2):
        if i == 0:
            util.printcolor(util.RED,f"Performing Change PIN with valid pinUvAuthToken")
        if i == 1:
            util.printcolor(util.RED,f"Performing Change PIN with invalidate pinUvAuthToken")


        util.APDUhex("00a4040008a0000006472f0001", "Select applet")
        util.APDUhex("80100000010400", "GetInfo")
        
        response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
        if status != "00":
            util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
        cbor_bytes = binascii.unhexlify(response[2:])
        decoded = cbor2.loads(cbor_bytes)
        peer_key = decoded.get(1)
        key_agreement, shared_secret = encapsulate_protocol1(peer_key)
        
        current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
        pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

        padded_new_pin = pad_pin(new_pin)
        util.printcolor(util.ORANGE, f"Current PIN : {current_pin}")
        util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
        util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(padded_new_pin)}")
        newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

        # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
        hmac_data = newPinEnc + pinHashEnc
        auth = hmac_sha256(shared_secret, hmac_data)
        pinAuth = auth[:16]

        if i == 0:
            apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
            invalidatePinAuth = pinAuth
        else:
            apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, invalidatePinAuth, key_agreement)

        response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
        # if status != "00":
        #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol1(current_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin = pad_pin(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {current_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(padded_new_pin)}")
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol1_InvalidParameters(current_pin: str, new_pin: str, mode: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    if mode == "invalidKeyAgreement" or mode == "invalidKeyAgreementChangePin":
        key_agreement, shared_secret = wrong_Encapsulate_protocol1(peer_key)
    else:
        key_agreement, shared_secret = encapsulate_protocol1(peer_key)
            
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    if mode == "invalidPinHashEncChangePin":
        tempPinHashEncStr = util.toHex(pinHashEnc)
        tempPinHashEncStr = "A0A0A0A0A0" + tempPinHashEncStr[10:]
        util.printcolor(util.GREEN, f"PinHashEncStr : {tempPinHashEncStr}")
        pinHashEnc = bytes.fromhex(tempPinHashEncStr)
    
    if mode == "invalidPinHashEncChangePin1":
        # tempPinHashEncStr = util.toHex(pinHashEnc)
        tempPinHashEncStr = util.toHex(os.urandom(16))
        util.printcolor(util.GREEN, f"PinHashEncStr : {tempPinHashEncStr}")
        pinHashEnc = bytes.fromhex(tempPinHashEncStr)

    padded_new_pin = pad_pin(new_pin)

    if mode == "newPinEncNotPaddedto64Bytes":
        padded_new_pin = wrong_pad_pin(new_pin)
        

    
    if mode == "nonZeroPadding":
        padded_new_pin_index = 33
        padded_new_pin_str = util.toHex(padded_new_pin)
        hex_index = padded_new_pin_index * 2
        new_byte_hex = "abcdef"

        padded_new_pin_str = (
            padded_new_pin_str[:hex_index] +
            new_byte_hex +
            padded_new_pin_str[hex_index + 2:]
        )
        padded_new_pin  = bytes.fromhex(padded_new_pin_str)[:64]

    util.printcolor(util.ORANGE, f"Current PIN : {current_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(padded_new_pin)}")
   
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

    if mode == "malformedNewPINEnc":
        sharedSecretStr = util.toHex(shared_secret)
        sharedSecretStr = "0123" + sharedSecretStr[4:]
        shared_secret = bytes.fromhex(sharedSecretStr)
        newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)


    if mode == "invalidNewPinEncChangePin":
        tempNewPinEncStr = util.toHex(newPinEnc)
        tempNewPinEncStr = tempNewPinEncStr[2:]
        util.printcolor(util.GREEN, f"NewPinEncStr : {tempNewPinEncStr}")
        newPinEnc = bytes.fromhex(tempNewPinEncStr)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    if mode == "invalidPinUvAuthParamChangePin":
        tempPinAuthStr = util.toHex(pinAuth)
        tempPinAuthStr = "A0A0A0A0A0" + tempPinAuthStr[10:]
        util.printcolor(util.GREEN, f"PinAuthStr : {tempPinAuthStr}")
        pinAuth = bytes.fromhex(tempPinAuthStr)

    apdu = createCBORchangePIN_protocol1_InvalidParameters(pinHashEnc, newPinEnc, pinAuth, key_agreement,mode)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol1_newPINWithoutPadding(current_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
    
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)

    padded_new_pin =util.withoupadded(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {current_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(padded_new_pin)}")
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)

   # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]

    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol2_invalidatePinAuth(old_pin, new_pin):
    for i in range(2):
        if i == 0:
            util.printcolor(util.RED,f"Performing Change PIN with valid pinUvAuthToken")
        if i == 1:
            util.printcolor(util.RED,f"Performing Change PIN with invalidate pinUvAuthToken")

        util.APDUhex("00a4040008a0000006472f0001","Select applet")
        #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
        cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
        if status != "00":
            util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
        cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
        decoded_data = cbor2.loads(cbor_bytes)
        key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

        oldPinHash = util.sha256(old_pin.encode())[:16]
        pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

        newPinPadded = util.pad_pin(new_pin)
        util.printcolor(util.ORANGE, f"Current PIN : {old_pin}")
        util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
        util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(newPinPadded)}")
        newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

        #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
        combined = newPinEnc + pinHashEnc
        hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
        pinAuth = hmac_value[:32]

        if i == 0:
            apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
            invalidatePinAuth = pinAuth
        else:
            apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, invalidatePinAuth, key_agreement)

        response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
        # if status != "00":
        #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status


def changePINProtocol2(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = pad_pin(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {old_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(newPinPadded)}")
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol2_InvalidParameters(old_pin, new_pin, mode):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    
    if mode == "invalidKeyAgreement" or mode == "invalidKeyAgreementChangePin":
        key_agreement, sharedSecret = util.wrongencapsulate(decoded_data[1])
    else:
        key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)


    if mode == "invalidPinHashEncChangePin":
        tempPinHashEncStr = util.toHex(pinHashEnc)
        tempPinHashEncStr = "A0A0A0A0A0" + tempPinHashEncStr[10:]
        util.printcolor(util.GREEN, f"PinHashEncStr : {tempPinHashEncStr}")
        pinHashEnc = bytes.fromhex(tempPinHashEncStr)

    if mode == "invalidPinHashEncChangePin2":
        # tempPinHashEncStr = util.toHex(pinHashEnc)
        tempPinHashEncStr = util.toHex(os.urandom(32))
        util.printcolor(util.GREEN, f"PinHashEncStr : {tempPinHashEncStr}")
        pinHashEnc = bytes.fromhex(tempPinHashEncStr)

    newPinPadded = util.pad_pin(new_pin)

    if mode == "newPinEncNotPaddedto64Bytes":
        newPinPadded = util.pad_pin_not_64bytes(new_pin)

    if mode == "nonZeroPadding":
        padded_new_pin_index = 32
        padded_new_pin_str = util.toHex(newPinPadded)
        hex_index = padded_new_pin_index * 2
        new_byte_hex = "abcd"

        padded_new_pin_str = (
            padded_new_pin_str[:hex_index] +
            new_byte_hex +
            padded_new_pin_str[hex_index + 2:]
        )
        newPinPadded  = bytes.fromhex(padded_new_pin_str)[:64]

    util.printcolor(util.ORANGE, f"Current PIN : {old_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(newPinPadded)}")
    
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    if mode == "malformedNewPINEnc":
        newPinPaddedStr = util.toHex(sharedSecret[32:])
        newPinPaddedStr = newPinPaddedStr[:-6] + "123456"
        sharedSecret = bytes.fromhex(newPinPaddedStr)
        newPinEnc = util.aes256_cbc_encrypt(sharedSecret, newPinPadded)

    if mode == "invalidNewPinEncChangePin":
        tempNewPinEncStr = util.toHex(newPinEnc)
        tempNewPinEncStr = tempNewPinEncStr[2:]
        util.printcolor(util.GREEN, f"NewPinEncStr : {tempNewPinEncStr}")
        newPinEnc = bytes.fromhex(tempNewPinEncStr)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    if mode == "invalidPinUvAuthParamChangePin":
        tempPinAuthStr = util.toHex(pinAuth)
        tempPinAuthStr = "A0A0A0A0A0" + tempPinAuthStr[10:]
        util.printcolor(util.GREEN, f"PinAuthStr : {tempPinAuthStr}")
        pinAuth = bytes.fromhex(tempPinAuthStr)

    apdu = createCBORchangePIN_protocol2_InvalidParameters(pinHashEnc, newPinEnc, pinAuth, key_agreement, mode)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status

def changePINProtocol2_newPINWithoutPadding(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    if status != "00":
        util.printcolor(util.RED,f"KEY AGREEMENT(0x02) FAILED WITH STATUS CODE : {status}")
    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.withoupadded(new_pin)
    util.printcolor(util.ORANGE, f"Current PIN : {old_pin}")
    util.printcolor(util.ORANGE, f"New PIN : {new_pin}")
    util.printcolor(util.ORANGE, f"Padded New PIN : {util.toHex(newPinPadded)}")
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    # if status != "00":
    #     util.printcolor(util.RED,f"CHANGE PIN(0x04) FAILED WITH STATUS CODE : {status}")
    return response , status


def changePINOnlyWithPinAuthToken(old_pin, new_pin, pinAuth):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:16]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    # combined = newPinEnc + pinHashEnc
    # hmac_value = util.hmac_sha256(sharedSecret[:32], combined)

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)

def changePINIncorrectPinHash(old_pin, new_pin):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    #util.printcolor(util.YELLOW, "Getting authenticator public key (keyAgreement)")
    cardPublicKeyHex, status = util.APDUhex("801000000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)

    cbor_bytes = binascii.unhexlify(cardPublicKeyHex[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, sharedSecret = util.encapsulate(decoded_data[1])

    oldPinHash = util.sha256(old_pin.encode())[:8]
    pinHashEnc = util.aes256_cbc_encrypt(sharedSecret[32:], oldPinHash)

    newPinPadded = util.pad_pin(new_pin)
    newPinEnc = util.aes256_cbc_encrypt(sharedSecret[32:], newPinPadded)

    #Compute pinAuth (first 16 bytes of HMAC over newPinEnc || pinHashEnc)
    combined = newPinEnc + pinHashEnc
    hmac_value = util.hmac_sha256(sharedSecret[:32], combined)
    pinAuth = hmac_value[:32]

    apdu = createCBORchangePIN_protocol2(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)


def createCBORchangePIN(pinHashenc, newPINenc, auth, key_agreement):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    cbor_newPINenc   = cbor2.dumps(newPINenc).hex().upper()
    cbor_auth        = cbor2.dumps(auth).hex().upper()
    dataCBOR = "A6"
    dataCBOR = dataCBOR + "01"+ "02" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "04" # changePIN
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "04"+ cbor_auth
    dataCBOR = dataCBOR + "05"+ cbor_newPINenc
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    util.printcolor(util.BLUE,dataCBOR)
    util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80108000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand

def createGetPINtokenProtocol2(pinHashenc, key_agreement):
    
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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
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
        return "80100000" + lc + full_data  # single string

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
            p1 = "00"
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

    return result, status

def makeCredProtocol2(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
       
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

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

    return result, status

import credBlob
import getAsseration
def extract_authdata_from_makecredential_response(hex_response):
    response_bytes = bytes.fromhex(hex_response)

    # Check status byte
    if response_bytes[0] != 0x00:
        raise ValueError(f"CTAP error: 0x{response_bytes[0]:02X}")

    # Decode CBOR response
    cbor_payload = response_bytes[1:]
    decoded_cbor = cbor2.loads(cbor_payload)

    print("Decoded CBOR keys:", decoded_cbor.keys())  # Should show [1, 2, 3]

    # Extract authData (it's under key 2)
    authdata = decoded_cbor.get(2)
    if not isinstance(authdata, bytes):
        raise TypeError("authData must be of type bytes")

    print("authdata (hex):", authdata.hex())
    return authdata

def authParsing(response):
    print("response",response)
    authdata=credBlob.extract_authdata_from_makecredential_response(response)
    print("authdata (hex):", authdata.hex())
    credential_info = getAsseration.parse_authdata(authdata)
    credentialId = credential_info["credentialId"]
    print("credid",credentialId)
    return credentialId


def makeAssertionProtocol2(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    pinToken, pubkey = getPINtokenPubkeyProtocol2(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")
    
    apdu = createCBORmakeAssertionProtocol2(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)
    return result, status


def createCBORmakeAssertionProtocol2(cryptohash, rp, pinAuthToken, credId):
    allow_list = [{
        
        "id": bytes.fromhex(credId),
        "type": "public-key"
    }]

    # CBOR encoding
    cbor_rp            = cbor2.dumps(rp).hex().upper()               # 0x01: rpId
    cbor_hash          = cbor2.dumps(cryptohash).hex().upper()       # 0x02: clientDataHash
    cbor_allowlist     = cbor2.dumps(allow_list).hex().upper()       # 0x03: allowList
    cbor_pinAuthToken  = cbor2.dumps(pinAuthToken).hex().upper()     # 0x06: pinAuth
    pin_protocol       = "02"                                        # 0x07: pinProtocol = 2

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
    apdu = "80100000" + format(length, '02X') + full_payload
    return apdu


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

        APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
        return APDUcommand 

def setpinProtocol2(pin):
    util.APDUhex("00A4040008A0000006472F0001", "Select applet")
    cardPublickey, status= util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)
    cbor_bytes   = binascii.unhexlify(cardPublickey[2:])
    decoded_data = cbor2.loads(cbor_bytes)
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    
    #Fido Alliance says to pad the PIN with 0x00 for 64 length
    newPinEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:], util.pad_pin(pin))
    auth       = util.hmac_sha256(shareSecretKey[:32], newPinEnc ) # always 32 byte result
    pinSetAPDU = createCBOR(newPinEnc, auth, key_agreement)    

    response , status  = util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x03 SetPIN", checkflag=True)
    return response, status

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

def wrong_Encapsulate_protocol1(peer_cose_key):
    backend = default_backend()
    sk = ec.generate_private_key(ec.SECP256R1(), backend)
    pub = sk.public_key().public_numbers()
    # b = int2bytes(pub.x, 32)
    # str = util.toHex(b)
    # str = "123456" + str[6:]
    # b = bytes.fromhex(str)
    key_agreement = {
        1: 2,    # kty: EC2
        3: -25,  # alg: -25 (not actually used)
        -1: 3,   # crv: P-256
        -2: int2bytes(pub.x, 32),      #int2bytes(pub.x, 32),
        -3: int2bytes(pub.x, 32),      #int2bytes(pub.y, 32),
    }
    peer_x = bytes2int(peer_cose_key[-2])
    peer_y = bytes2int(peer_cose_key[-3])
    peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1()).public_key(backend)
    shared_point = sk.exchange(ec.ECDH(), peer_pub)
    shared_secret = hashlib.sha256(shared_point).digest()  # Protocol 1 KDF
    return key_agreement, shared_secret

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

    # if validate:
    #     if len(pin_bytes) < 6:
    #         raise ValueError("PIN must be at least 6 bytes")
    #     if len(pin_bytes) > 64:
    #         raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(64, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def wrong_pad_pin(pin: str, validate: bool = True) -> bytes:
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string")
    pin_bytes = pin.encode('utf-8')

    # if validate:
    #     if len(pin_bytes) < 6:
    #         raise ValueError("PIN must be at least 6 bytes")
    #     if len(pin_bytes) > 64:
    #         raise ValueError("PIN must not exceed 64 bytes")

    return pin_bytes.ljust(67, b'\x00')  # Protocol 1: pad with 0x00 to 64 bytes

def setpinProtocol1(pin):
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
    response , status = util.APDUhex(apdu, "Client PIN subcmd 0x03 SetPIN", checkflag=True)
    return response , status

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def aes256_cbc_encrypt(shared_secret: bytes, data: bytes) -> bytes:
    iv = b'\x00' * 16  # Protocol 1: All-zero IV
    if len(data) % 16 != 0:
        data += b'\x00' * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


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


def getAsserationProtocol2(curpin, clientDataHash, rp,response):
    credId =authParsing(response)
    response, status  = makeAssertionProtocol2(curpin, clientDataHash, rp, credId)
    return response, status

def makeCredProtocol1(curpin, clientDataHash, rp, user):
    util.printcolor(util.YELLOW,f" Using  PIN  data: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001","Select applet")
    util.APDUhex("80100000010400","GetInfo")
       
    pinToken = getPINtokenPubkeyProtocol1(curpin)

    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN,f"  pinAuthToken: {pinAuthToken.hex()}")

    makeCredAPDU = createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthToken);
    result,status = util.APDUhex(makeCredAPDU,"Client PIN command as subcmd 0x01 make Credential", checkflag=True);
    return result , status
   
def createCBORmakeCredProtocol1(clientDataHash, rp, user, pinAuthToken):

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

    option  = {"rk": True}

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
    dataCBOR = dataCBOR + "06" + ex
    dataCBOR = dataCBOR + "07" + rk
    dataCBOR = dataCBOR + "08"+ cbor_pinAuthToken
    dataCBOR = dataCBOR + "09"+ "01"               # pin protocol V1 assumed

    length = (len(dataCBOR) >> 1) +1    #have to add the 01 command for CBOR data passed

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "01" + dataCBOR
    return APDUcommand

def getPINtokenPubkeyProtocol1(pin):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")

    
    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
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
    apdu = "80100000" + format(len(encoded) + 1, '02X') + "06" + binascii.hexlify(encoded).decode().upper()
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


def getAsserationProtocol1(pin, username, rp,response):
    hashchallenge = os.urandom(32)
    credId = authParsing(response)
    result, status = authenticateUser(pin, hashchallenge, rp, credId)
    return result, status

def authenticateUser(curpin, clientDataHash, rp, credId):
    util.printcolor(util.YELLOW, f"Using PIN: {curpin}")
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")

    pinToken = getPINtokenPubkeyProtocol1(curpin)
    pinAuthToken = util.hmac_sha256(pinToken, clientDataHash)[:16]
    #util.printcolor(util.CYAN, f"pinAuthToken: {pinAuthToken.hex()}")

    apdu = createCBORmakeAssertionProtocol1(clientDataHash, rp, pinAuthToken, credId)
    result, status = util.APDUhex(apdu, "GetAssertion 0x02", checkflag=True)

    return result, status


def createCBORmakeAssertionProtocol1(cryptohash, rp, pinAuthToken, credId):
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
    apdu = "80100000" + format(length, '02X') + full_payload
    return apdu

def newMinPinLength_forcechangePin_Protocol1(pinToken, subCommand, forceChangePIN):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    pinUvAuthParam = pinUvAuthParam[:16]

    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status


def newMinPinLength_forcechangePin_withMinLength_Protocol1(pinToken, subCommand, minimumLength, forceChangePIN):

    subCommandParams = {
        0x01: minimumLength,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True/False
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    pinUvAuthParam = pinUvAuthParam[:16]

    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 1,               # pinUvAuthProtocol = 1
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status

def newMinPinLength_forcechangePin_withMinLength_Protocol2(pinToken, subCommand, minimumLength, forceChangePIN):

    subCommandParams = {
        0x01: minimumLength,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True/False
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status

def newMinPinLength_forcechangePin_Protocol2(pinToken, subCommand, forceChangePIN):

    subCommandParams = {
        0x01: 6,      # newMinPINLength (set to 8, larger than typical default of 4)
        0x03: forceChangePIN   # forcePINChange = True
    }

    subCommandParams_cbor = cbor2.dumps(subCommandParams)
    
    # Message: 32x0xFF || 0x0D || subCommand
    message = b'\xFF' * 32 + b'\x0D' + bytes([subCommand])+ subCommandParams_cbor
    print(f"Message: {message.hex()}")  # (32 bytes) + 0d01

    # Compute pinUvAuthParam using HMAC-SHA256, full 32 bytes
    pinUvAuthParam = util.hmac_sha256(pinToken, message)
    print(f"pinUvAuthParam: {pinUvAuthParam.hex()} (length: {len(pinUvAuthParam)})")

    cbor_map = {
        0x01: subCommand,      # newMinPINLength
        0x02:subCommandParams,
        0x03: 2,               # pinUvAuthProtocol = 2
        0x04: pinUvAuthParam
    }

    cbor_bytes = cbor2.dumps(cbor_map)
    lc = len(cbor_bytes) + 1

    apdu = "80100000" + format(lc, "02X") + "0D" + cbor_bytes.hex().upper()
    response, status = util.APDUhex(apdu, "ForcePINChange subcmd 0x0D", checkflag=True)
    return response, status


def createGetPINtokenWithPermisionProtocol2(pinHashenc, key_agreement,permission):
    
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

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def createGetPINtokenWithPermisionProtocol1(pinHashenc, key_agreement,permission):
    
    platformCOSKEY   = cbor2.dumps(key_agreement).hex().upper()
    cbor_pinHashenc  = cbor2.dumps(pinHashenc).hex().upper()
    permission_hex   = cbor2.dumps(permission).hex().upper() 
    
    dataCBOR = "A5"
    dataCBOR = dataCBOR + "01"+ "01" # Fido2 protocol 2
    dataCBOR = dataCBOR + "02"+ "09" # getPinUvAuthTokenUsingPinWithPermissions 
    
    dataCBOR = dataCBOR + "03"+ platformCOSKEY
    dataCBOR = dataCBOR + "06"+ cbor_pinHashenc  
    dataCBOR = dataCBOR + "09"+ permission_hex

    length = (len(dataCBOR) >> 1) +1    #have to add the 06

    #util.printcolor(util.BLUE,dataCBOR)
    #util.hex_string_to_cbor_diagnostic(dataCBOR)

    APDUcommand = "80100000" +  format(length, '02X') + "06" + dataCBOR
    return APDUcommand


def getPINTokenWithPermissionProtocol2(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    cardPublickey, status = util.APDUhex("801000000606a20102020200","Client PIN subcmd 0x02 getKeyAgreement",True)

    
    cbor_bytes    = binascii.unhexlify(cardPublickey[2:])
    decoded_data  = cbor2.loads(cbor_bytes)
    pubkey        = cardPublickey[6:]
    #util.printcolor(util.ORANGE,f"{pubkey}")
    key_agreement, shareSecretKey = util.encapsulate(decoded_data[1])

    pin_hash    = util.sha256(curpin.encode())[:16]
    pinHashEnc  = util.aes256_cbc_encrypt(shareSecretKey[32:],pin_hash)

    pinSetAPDU =createGetPINtokenWithPermisionProtocol2(pinHashEnc,key_agreement,permission)

    hexstring, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (hexstring[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {hexstring} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {hexstring}")

    byte_array = bytes.fromhex(hexstring[2:])
    cbor_data = cbor2.loads(byte_array)                                                                                                
    first_key = sorted(cbor_data.keys())[0]
    pinToken = cbor_data[first_key]
    #util.printcolor(util.CYAN, f" pinToken: {pinToken.hex()}")

    token =  util.aes256_cbc_decrypt(shareSecretKey[32:],pinToken[:16],pinToken[-32:])

    return token, pubkey


def getPINTokenWithPermissionProtocol1(curpin,permission):
    util.APDUhex("00a4040008a0000006472f0001","Select applet")

    response, status = util.APDUhex("801000000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)

    pin_hash = hashlib.sha256(curpin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, pin_hash)


    pinSetAPDU =createGetPINtokenWithPermisionProtocol1(pinHashEnc,key_agreement,permission)

    response, status= util.APDUhex(pinSetAPDU,"Client PIN command as subcmd 0x05 getPINtoken", checkflag=True);

    if (response[0:2] != "00"):
        util.printcolor(util.RED, f" pinToken ERROR: {response} maybe you need to SET the PIN??")
        os._exit(0)
    print(f"getToken success: {response}")

    cbor_resp = cbor2.loads(binascii.unhexlify(response[2:]))
    enc_pin_token = cbor_resp.get(2)  # Field 0x02 = pinToken (encrypted)
    if not enc_pin_token:
        raise ValueError("No pinToken returned from authenticator")

    pin_token = aes256_cbc_decrypt(shared_secret, enc_pin_token)
    #util.printcolor(util.GREEN, f"PIN Token (decrypted): {binascii.hexlify(pin_token).decode()}")
    return pin_token


def change_client_pin_swapping_protocol2(old_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
   
    util.printcolor(util.YELLOW,"KEY AGREEMENT BY PROTOCOL 1 -> CHANGE PIN BY PROTOCOL 2")
    cardPublicKeyHex, status = util.APDUhex("801080000606a20101020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
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
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response, status


def change_client_pin_swapping_protocol1(current_pin: str, new_pin: str):
    util.APDUhex("00a4040008a0000006472f0001", "Select applet")
    util.APDUhex("80100000010400", "GetInfo")
   
    util.printcolor(util.YELLOW,"KEY AGREEMENT BY PROTOCOL 2 -> CHANGE PIN BY PROTOCOL 1")
    response, status = util.APDUhex("801080000606a20102020200", "Client PIN subcmd 0x02 getKeyAgreement", checkflag=True)
    cbor_bytes = binascii.unhexlify(response[2:])
    decoded = cbor2.loads(cbor_bytes)
    peer_key = decoded.get(1)
    key_agreement, shared_secret = encapsulate_protocol1(peer_key)
   
    current_pin_hash = hashlib.sha256(current_pin.encode()).digest()[:16]
    pinHashEnc = aes256_cbc_encrypt(shared_secret, current_pin_hash)
 
    padded_new_pin = pad_pin(new_pin)
    newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)
    # newPinEnc = aes256_cbc_encrypt(shared_secret, padded_new_pin)
 
    # pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)
    hmac_data = newPinEnc + pinHashEnc
    auth = hmac_sha256(shared_secret, hmac_data)
    pinAuth = auth[:16]
 
    apdu = createCBORchangePIN_protocol1(pinHashEnc, newPinEnc, pinAuth, key_agreement)
    response, status = util.APDUhex(apdu, "Client PIN subcmd 0x04 ChangePIN", checkflag=True)
    return response, status
 